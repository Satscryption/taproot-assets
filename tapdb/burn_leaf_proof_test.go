package tapdb

import (
	"bytes"
	"context"
	"database/sql"
	"math/rand"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/tapfreighter"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
)

// prevProofFile builds a one-proof file and the prev ID its tip
// satisfies.
func prevProofFile(t *testing.T) (*proof.File, asset.PrevID) {
	t.Helper()

	a := asset.RandAsset(t, asset.Normal)
	p := randProof(t, a)
	file, err := proof.NewFile(proof.V0, *p)
	require.NoError(t, err)

	prevID := asset.PrevID{
		OutPoint: p.OutPoint(),
		ID:       a.ID(),
		ScriptKey: asset.ToSerialized(
			a.ScriptKey.PubKey,
		),
	}

	return file, prevID
}

// suffixSpending builds a transition proof whose witnesses spend the
// given inputs. split places those witnesses on the split root, which
// is where a split burn records them.
func suffixSpending(t *testing.T, prevIDs []asset.PrevID,
	split bool) *proof.Proof {

	t.Helper()

	witnesses := make([]asset.Witness, len(prevIDs))
	for i := range prevIDs {
		id := prevIDs[i]
		witnesses[i] = asset.Witness{PrevID: &id}
	}

	gen := asset.RandGenesis(t, asset.Normal)
	burnAsset := asset.RandAssetWithValues(
		t, gen, nil, asset.RandScriptKey(t),
	)
	if split {
		root := burnAsset.Copy()
		root.PrevWitnesses = witnesses

		emptyNodes := make([]mssmt.Node, mssmt.MaxTreeLevels)
		for i := range emptyNodes {
			emptyNodes[i] = mssmt.EmptyTree[mssmt.MaxTreeLevels-i]
		}

		burnAsset.PrevWitnesses = []asset.Witness{{
			PrevID: &asset.PrevID{},
			SplitCommitment: &asset.SplitCommitment{
				Proof:     *mssmt.NewProof(emptyNodes),
				RootAsset: *root,
			},
		}}
	} else {
		burnAsset.PrevWitnesses = witnesses
	}

	suffix := randProof(t, burnAsset)
	suffix.BlockHeight = 1234
	// A timestamp that fits in the header's uint32 field, so an
	// encode/decode round trip preserves it.
	suffix.BlockHeader = wire.BlockHeader{
		Nonce:     7,
		Timestamp: time.Unix(1_700_000_000, 0),
	}
	suffix.AdditionalInputs = nil

	return suffix
}

// TestBurnLeafProof checks that the burn leaf embeds every spent input
// and leaves the suffix it was built from alone.
func TestBurnLeafProof(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name      string
		numInputs int
		split     bool
	}{
		{name: "single input", numInputs: 1},
		{name: "multiple inputs", numInputs: 3},
		{name: "split burn", numInputs: 2, split: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files := make(map[asset.PrevID]*proof.File)
			prevIDs := make([]asset.PrevID, 0, tc.numInputs)
			for i := 0; i < tc.numInputs; i++ {
				file, prevID := prevProofFile(t)
				files[prevID] = file
				prevIDs = append(prevIDs, prevID)
			}

			// An unspent input must not be embedded.
			extra, extraID := prevProofFile(t)
			files[extraID] = extra

			suffix := suffixSpending(t, prevIDs, tc.split)
			var before bytes.Buffer
			require.NoError(t, suffix.Encode(&before))

			burnProof, err := tapfreighter.BurnLeafProof(suffix, files)
			require.NoError(t, err)

			require.EqualValues(t, 1234, burnProof.BlockHeight)
			require.Equal(
				t, suffix.BlockHeader.Nonce,
				burnProof.BlockHeader.Nonce,
			)
			require.Equal(
				t, suffix.BlockHeader.Timestamp.Unix(),
				burnProof.BlockHeader.Timestamp.Unix(),
			)
			require.Len(
				t, burnProof.AdditionalInputs, tc.numInputs,
			)
			for _, in := range burnProof.AdditionalInputs {
				require.Equal(t, 1, in.NumProofs())
			}

			var encoded bytes.Buffer
			require.NoError(t, burnProof.Encode(&encoded))
			require.Less(
				t, encoded.Len(), proof.FileMaxProofSizeBytes,
			)

			var decoded proof.Proof
			require.NoError(t, decoded.Decode(
				bytes.NewReader(encoded.Bytes()),
			))
			require.Len(
				t, decoded.AdditionalInputs, tc.numInputs,
			)

			var after bytes.Buffer
			require.NoError(t, suffix.Encode(&after))
			require.Equal(t, before.Bytes(), after.Bytes())
			require.Empty(t, suffix.AdditionalInputs)
		})
	}
}

// TestBurnLeafProofSize records encoded leaf sizes and keeps them
// under the single-proof limit. Embedding the primary input grows the
// leaf by about one input file, not by a second copy of the leaf.
func TestBurnLeafProofSize(t *testing.T) {
	t.Parallel()

	for _, numInputs := range []int{1, 3, 5} {
		files := make(map[asset.PrevID]*proof.File)
		prevIDs := make([]asset.PrevID, 0, numInputs)
		for i := 0; i < numInputs; i++ {
			file, prevID := prevProofFile(t)
			files[prevID] = file
			prevIDs = append(prevIDs, prevID)
		}

		suffix := suffixSpending(t, prevIDs, false)
		var bare bytes.Buffer
		require.NoError(t, suffix.Encode(&bare))

		burnProof, err := tapfreighter.BurnLeafProof(suffix, files)
		require.NoError(t, err)

		var encoded bytes.Buffer
		require.NoError(t, burnProof.Encode(&encoded))
		t.Logf("burn leaf size num_inputs=%d bare=%d leaf=%d",
			numInputs, bare.Len(), encoded.Len())

		require.Greater(t, encoded.Len(), bare.Len())
		require.Less(t, encoded.Len(), proof.FileMaxProofSizeBytes)
	}
}

// TestBurnLeafProofErrors tests the closed failure modes.
func TestBurnLeafProofErrors(t *testing.T) {
	t.Parallel()

	file, prevID := prevProofFile(t)
	files := map[asset.PrevID]*proof.File{prevID: file}
	suffix := suffixSpending(t, []asset.PrevID{prevID}, false)

	t.Run("nil suffix", func(t *testing.T) {
		_, err := tapfreighter.BurnLeafProof(nil, files)
		require.ErrorContains(t, err, "suffix is nil")
	})

	t.Run("duplicate witness", func(t *testing.T) {
		dup := suffixSpending(
			t, []asset.PrevID{prevID, prevID}, false,
		)
		_, err := tapfreighter.BurnLeafProof(dup, files)
		require.ErrorContains(t, err, "duplicate burn input")
	})

	t.Run("missing input", func(t *testing.T) {
		_, err := tapfreighter.BurnLeafProof(suffix, map[asset.PrevID]*proof.File{})
		require.ErrorContains(t, err, "missing proof")
	})

	t.Run("empty input", func(t *testing.T) {
		empty := map[asset.PrevID]*proof.File{
			prevID: proof.NewEmptyFile(proof.V0),
		}
		_, err := tapfreighter.BurnLeafProof(suffix, empty)
		require.ErrorContains(t, err, "empty proof")
	})

	t.Run("mismatched input", func(t *testing.T) {
		other, _ := prevProofFile(t)
		_, err := tapfreighter.BurnLeafProof(suffix, map[asset.PrevID]*proof.File{
			prevID: other,
		})
		require.ErrorContains(t, err, "proof mismatch")
	})
}

// TestRebuildBurnLeafEmbedsInputProvenance drives a burn transfer
// through the porter rebuild. The burn leaf must carry the spent
// input, and the stored proof file must still keep that input as its
// prefix rather than an additional input.
func TestRebuildBurnLeafEmbedsInputProvenance(t *testing.T) {
	t.Parallel()

	db := NewTestDB(t)
	_, assetsStore := newAssetStoreFromDB(db.BaseDB)
	ctx := context.Background()

	executor := NewTransactionExecutor(
		db, func(tx *sql.Tx) *sqlc.Queries {
			return db.WithTx(tx)
		},
	)

	targetScriptKey := asset.NewScriptKeyBip86(keychain.KeyDescriptor{
		PubKey: test.RandPubKey(t),
		KeyLocator: keychain.KeyLocator{
			Family: test.RandInt[keychain.KeyFamily](),
			Index:  uint32(test.RandInt[int32]()),
		},
	})

	assetGen := newAssetGenerator(t, 1, 1)
	assetGen.genAssets(t, assetsStore, []assetDesc{{
		assetGen:    assetGen.assetGens[0],
		anchorPoint: assetGen.anchorPoints[0],
		scriptKey:   &targetScriptKey,
		amt:         16,
	}})

	allAssets, err := assetsStore.FetchAllAssets(ctx, true, false, nil)
	require.NoError(t, err)
	require.Len(t, allAssets, 1)
	inputAsset := allAssets[0]
	assetID := inputAsset.ID()

	inputAnchorPoint := wire.OutPoint{
		Hash:  assetGen.anchorTxs[0].TxHash(),
		Index: 0,
	}
	inputPrevID := asset.PrevID{
		OutPoint: inputAnchorPoint,
		ID:       assetID,
		ScriptKey: asset.ToSerialized(
			inputAsset.ScriptKey.PubKey,
		),
	}

	// The file the rebuild fetches. Its tip must be the spent
	// input, or the leaf is rejected as mismatched provenance.
	inputProof := randProof(t, inputAsset.Asset)
	inputProof.AnchorTx = *assetGen.anchorTxs[0]
	inputProof.InclusionProof.OutputIndex = 0
	inputFile, err := proof.NewFile(proof.V0, *inputProof)
	require.NoError(t, err)
	var inputFileBuf bytes.Buffer
	require.NoError(t, inputFile.Encode(&inputFileBuf))

	var inputAssetDBID int64
	err = db.DB.QueryRowContext(
		ctx, "SELECT assets.asset_id FROM assets "+
			"JOIN script_keys ON assets.script_key_id = "+
			"script_keys.script_key_id "+
			"WHERE script_keys.tweaked_script_key = $1",
		inputAsset.ScriptKey.PubKey.SerializeCompressed(),
	).Scan(&inputAssetDBID)
	require.NoError(t, err)
	require.NoError(t, db.UpsertAssetProofByID(ctx, ProofUpdateByID{
		AssetID:   inputAssetDBID,
		ProofFile: inputFileBuf.Bytes(),
	}))

	newAnchorTx := wire.NewMsgTx(2)
	newAnchorTx.AddTxIn(&wire.TxIn{PreviousOutPoint: inputAnchorPoint})
	newAnchorTx.AddTxOut(&wire.TxOut{
		PkScript: bytes.Repeat([]byte{0x01}, 34),
		Value:    1000,
	})
	newAnchorTx.AddTxOut(&wire.TxOut{
		PkScript: bytes.Repeat([]byte{0x02}, 34),
		Value:    1000,
	})
	anchorTxHash := newAnchorTx.TxHash()

	const burnAmt = 6
	burnKey := asset.NewScriptKey(asset.DeriveBurnKey(inputPrevID))
	burnAsset := inputAsset.Copy()
	burnAsset.ScriptKey = burnKey
	burnAsset.Amount = burnAmt
	burnAsset.PrevWitnesses = []asset.Witness{{
		PrevID:    &inputPrevID,
		TxWitness: [][]byte{{0x01}},
	}}
	require.True(t, burnAsset.IsBurn())
	burnSuffix := randProof(t, burnAsset)
	burnSuffixBytes, err := burnSuffix.Bytes()
	require.NoError(t, err)

	changeKey := asset.NewScriptKeyBip86(keychain.KeyDescriptor{
		PubKey: test.RandPubKey(t),
		KeyLocator: keychain.KeyLocator{
			Index:  uint32(rand.Int31()),
			Family: keychain.KeyFamily(rand.Int31()),
		},
	})
	changeAsset := inputAsset.Copy()
	changeAsset.ScriptKey = changeKey
	changeAsset.Amount = inputAsset.Amount - burnAmt
	changeAsset.PrevWitnesses = []asset.Witness{{
		PrevID:    &inputPrevID,
		TxWitness: [][]byte{{0x01}},
	}}
	require.False(t, changeAsset.IsBurn())
	changeSuffix := randProof(t, changeAsset)
	changeSuffixBytes, err := changeSuffix.Bytes()
	require.NoError(t, err)

	rootHash := [32]byte{0x10}
	makeAnchor := func(index uint32, script byte) tapfreighter.Anchor {
		return tapfreighter.Anchor{
			Value: 1000,
			OutPoint: wire.OutPoint{
				Hash:  anchorTxHash,
				Index: index,
			},
			InternalKey: keychain.KeyDescriptor{
				PubKey: test.RandPubKey(t),
				KeyLocator: keychain.KeyLocator{
					Family: keychain.KeyFamily(
						rand.Int31(),
					),
					Index: uint32(test.RandInt[int32]()),
				},
			},
			TaprootAssetRoot: bytes.Repeat([]byte{0x1}, 32),
			MerkleRoot:       bytes.Repeat([]byte{0x1}, 32),
			PkScript:         bytes.Repeat([]byte{script}, 34),
		}
	}

	parcel := &tapfreighter.OutboundParcel{
		AnchorTx:           newAnchorTx,
		AnchorTxHeightHint: 1450,
		TransferTime:       time.Now(),
		ChainFees:          100,
		Inputs: []tapfreighter.TransferInput{{
			PrevID: inputPrevID,
			Amount: inputAsset.Amount,
		}},
		Outputs: []tapfreighter.TransferOutput{{
			Anchor:         makeAnchor(0, 0x01),
			ScriptKey:      burnKey,
			ScriptKeyLocal: true,
			Amount:         burnAmt,
			WitnessData:    burnAsset.PrevWitnesses,
			SplitCommitmentRoot: mssmt.NewComputedNode(
				rootHash, 100,
			),
			ProofSuffix: burnSuffixBytes,
			Position:    0,
		}, {
			Anchor:         makeAnchor(1, 0x02),
			ScriptKey:      changeKey,
			ScriptKeyLocal: true,
			Amount:         inputAsset.Amount - burnAmt,
			WitnessData:    changeAsset.PrevWitnesses,
			SplitCommitmentRoot: mssmt.NewComputedNode(
				rootHash, 100,
			),
			ProofSuffix: changeSuffixBytes,
			Position:    1,
		}},
	}

	leaseOwner := fn.ToArray[[32]byte](test.RandBytes(32))
	err = executor.ExecTx(
		ctx, WriteTxOption(), func(q *sqlc.Queries) error {
			return assetsStore.ApplyPendingParcel(
				ctx, q, parcel, leaseOwner,
				time.Now().Add(time.Hour),
			)
		},
	)
	require.NoError(t, err)

	rebuild := func(nonce, height, txIndex uint32) (
		*tapfreighter.AssetConfirmEvent, []*tapfreighter.AssetBurn) {

		blockHash, header, merkle := blockContextFor(
			t, newAnchorTx, nonce,
		)
		conf, burns, err := assetsStore.RebuildConfirmEvent(
			ctx, newAnchorTx, blockHash, height, txIndex, header,
			merkle, "burn note",
		)
		require.NoError(t, err)

		return conf, burns
	}

	assertBurn := func(conf *tapfreighter.AssetConfirmEvent,
		burns []*tapfreighter.AssetBurn, height uint32,
		header wire.BlockHeader) {

		require.Len(t, burns, 1)
		require.Equal(t, "burn note", burns[0].Note)
		require.EqualValues(t, burnAmt, burns[0].Amount)
		require.Equal(
			t, header.Nonce, burns[0].Proof.BlockHeader.Nonce,
		)
		require.Equal(
			t, header.Version, burns[0].Proof.BlockHeader.Version,
		)
		require.Equal(
			t, header.MerkleRoot,
			burns[0].Proof.BlockHeader.MerkleRoot,
		)
		require.EqualValues(t, height, burns[0].Proof.BlockHeight)
		require.Equal(
			t, newAnchorTx.TxHash(),
			burns[0].Proof.AnchorTx.TxHash(),
		)

		// Exactly the spent input, once. A second copy would
		// both bloat the leaf and fail the duplicate check.
		require.Len(t, burns[0].Proof.AdditionalInputs, 1)
		require.Equal(
			t, 1, burns[0].Proof.AdditionalInputs[0].NumProofs(),
		)
		var leafBuf bytes.Buffer
		require.NoError(t, burns[0].Proof.Encode(&leafBuf))
		require.Less(t, leafBuf.Len(), proof.FileMaxProofSizeBytes)

		// The transfer proof file keeps the input as its
		// prefix. Embedding it again would grow every stored
		// burn proof by a full extra copy of the history.
		require.Len(t, conf.FinalProofs, 2)
		for _, annotated := range conf.FinalProofs {
			file := &proof.File{}
			err := file.Decode(bytes.NewReader(annotated.Blob))
			require.NoError(t, err)
			require.Equal(t, 2, file.NumProofs())

			last, err := file.ProofAt(1)
			require.NoError(t, err)
			require.Empty(t, last.AdditionalInputs)
			require.EqualValues(t, height, last.BlockHeight)
		}
	}

	conf, burns := rebuild(1, 600, 0)
	_, headerA, _ := blockContextFor(t, newAnchorTx, 1)
	assertBurn(conf, burns, 600, headerA)

	// A later witness context (re-org, or the buried delivery)
	// rebuilds the same provenance against the new block.
	confB, burnsB := rebuild(9, 700, 1)
	_, headerB, _ := blockContextFor(t, newAnchorTx, 9)
	assertBurn(confB, burnsB, 700, headerB)
	require.NotEqual(t, headerA, headerB)
}

// blockContextFor builds a block hash, header, and merkle proof for a
// confirmed anchor transaction.
func blockContextFor(t *testing.T, anchorTx *wire.MsgTx,
	nonce uint32) (chainhash.Hash, wire.BlockHeader, proof.TxMerkleProof) {

	t.Helper()

	header := wire.BlockHeader{
		Version:   1,
		Nonce:     nonce,
		Timestamp: time.Unix(1_700_000_000+int64(nonce), 0),
	}
	blockHash := header.BlockHash()

	merkle, err := proof.NewTxMerkleProof([]*wire.MsgTx{anchorTx}, 0)
	require.NoError(t, err)

	return blockHash, header, *merkle
}

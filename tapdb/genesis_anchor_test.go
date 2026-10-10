package tapdb

import (
	"bytes"
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/universe/supplycommit"
	"github.com/stretchr/testify/require"
)

// customMintTx builds a mint transaction that spends the genesis outpoint
// as input 0, carries an extra input, and places the pre-commit at output
// index 1. That is the shape of a custom-genesis mint.
func customMintTx(t *testing.T, genesis wire.OutPoint) *wire.MsgTx {
	t.Helper()

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: genesis})
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: test.RandOp(t)})
	tx.AddTxOut(&wire.TxOut{
		Value:    1000,
		PkScript: []byte{0x51, 0x20},
	})
	tx.AddTxOut(&wire.TxOut{
		Value:    2000,
		PkScript: []byte{0x51, 0x21},
	})

	return tx
}

// transferSpendingMint spends a mint output and does not spend the genesis
// outpoint.
func transferSpendingMint(mint *wire.MsgTx) *wire.MsgTx {
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  mint.TxHash(),
			Index: 0,
		},
	})
	tx.AddTxOut(&wire.TxOut{
		Value:    900,
		PkScript: []byte{0x00},
	})

	return tx
}

// anchorProof wraps an anchor transaction in the proof upsertAssetGen reads.
func anchorProof(t *testing.T, genesis asset.Genesis,
	anchor wire.MsgTx) *proof.Proof {

	t.Helper()

	proofAsset := asset.RandAsset(t, asset.Normal)
	proofAsset.Genesis = genesis
	proofAsset.GroupKey = nil
	proofAsset.PrevWitnesses = nil

	return &proof.Proof{
		BlockHeader: wire.BlockHeader{
			Timestamp: time.Unix(1, 0),
		},
		BlockHeight: 100,
		AnchorTx:    anchor,
		Asset:       *proofAsset,
	}
}

// genesisAnchorID returns the chain_txns id stored for the genesis outpoint.
func genesisAnchorID(t *testing.T, db *SqliteStore,
	genesis wire.OutPoint) int64 {

	t.Helper()

	ctx := context.Background()
	encoded, err := encodeOutpoint(genesis)
	require.NoError(t, err)

	points, err := db.GenesisPoints(ctx)
	require.NoError(t, err)

	for _, point := range points {
		if bytes.Equal(point.PrevOut, encoded) {
			require.True(t, point.AnchorTxID.Valid)
			return point.AnchorTxID.Int64
		}
	}

	t.Fatalf("genesis outpoint %v not found", genesis)
	return 0
}

// TestTransferProofKeepsCustomGenesisPreCommit upserts a custom-genesis
// mint proof and then a transfer proof. The genesis anchor and the
// unspent pre-commit query must still return the mint transaction and
// the caller-selected output index.
func TestTransferProofKeepsCustomGenesisPreCommit(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := NewTestDB(t)

	genesis := asset.RandGenesis(t, asset.Normal)
	mintTx := customMintTx(t, genesis.FirstPrevOut)
	const preCommitIdx = int32(1)

	_, err := upsertAssetGen(
		ctx, db, genesis, nil,
		anchorProof(t, genesis, *mintTx),
	)
	require.NoError(t, err)

	mintTxid := mintTx.TxHash()
	mintChain, err := db.FetchChainTx(ctx, mintTxid[:])
	require.NoError(t, err)
	require.Equal(t, mintChain.TxnID, genesisAnchorID(
		t, db, genesis.FirstPrevOut,
	))

	groupPriv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	groupKey := schnorr.SerializePubKey(groupPriv.PubKey())
	insertMintPreCommit(t, db, genesis, mintTx, preCommitIdx, groupKey)

	transfer := transferSpendingMint(mintTx)
	_, err = upsertAssetGen(
		ctx, db, genesis, nil,
		anchorProof(t, genesis, *transfer),
	)
	require.NoError(t, err)

	require.Equal(t, mintChain.TxnID, genesisAnchorID(
		t, db, genesis.FirstPrevOut,
	))

	rows, err := db.FetchUnspentMintSupplyPreCommits(ctx, groupKey)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	require.Equal(t, preCommitIdx, rows[0].TxOutputIndex)

	var got wire.MsgTx
	err = got.Deserialize(bytes.NewReader(rows[0].RawTx))
	require.NoError(t, err)
	require.Equal(t, mintTx.TxHash(), got.TxHash())
}

// insertMintPreCommit stores a local mint pre-commit at the given index
// of mintTx, bound to the genesis already inserted for that mint.
func insertMintPreCommit(t *testing.T, db *SqliteStore, genesis asset.Genesis,
	mintTx *wire.MsgTx, outIdx int32, groupKey []byte) {

	t.Helper()

	ctx := context.Background()
	batchDesc, _ := test.RandKeyDesc(t)
	batchKey := batchDesc.PubKey.SerializeCompressed()
	batchID, err := db.UpsertInternalKey(ctx, sqlc.UpsertInternalKeyParams{
		RawKey:    batchKey,
		KeyFamily: int32(batchDesc.Family),
		KeyIndex:  int32(batchDesc.Index),
	})
	require.NoError(t, err)

	genBytes, err := encodeOutpoint(genesis.FirstPrevOut)
	require.NoError(t, err)
	genID, err := db.UpsertGenesisPoint(ctx, genBytes)
	require.NoError(t, err)

	err = db.NewMintingBatch(ctx, sqlc.NewMintingBatchParams{
		BatchID:          batchID,
		HeightHint:       100,
		CreationTimeUnix: time.Now(),
	})
	require.NoError(t, err)

	_, err = db.BindMintingBatchWithTx(
		ctx, sqlc.BindMintingBatchWithTxParams{
			RawKey:    batchKey,
			GenesisID: sqlInt64(genID),
		},
	)
	require.NoError(t, err)

	internalDesc, _ := test.RandKeyDesc(t)
	internalID, err := db.UpsertInternalKey(
		ctx, sqlc.UpsertInternalKeyParams{
			RawKey: internalDesc.PubKey.SerializeCompressed(),
			KeyFamily: int32(
				internalDesc.KeyLocator.Family,
			),
			KeyIndex: int32(internalDesc.KeyLocator.Index),
		},
	)
	require.NoError(t, err)

	outpoint := wire.OutPoint{
		Hash:  mintTx.TxHash(),
		Index: uint32(outIdx),
	}
	var buf bytes.Buffer
	err = wire.WriteOutPoint(&buf, 0, 0, &outpoint)
	require.NoError(t, err)

	_, err = db.UpsertMintSupplyPreCommit(
		ctx, sqlc.UpsertMintSupplyPreCommitParams{
			TxOutputIndex:        outIdx,
			TaprootInternalKeyID: internalID,
			GroupKey:             groupKey,
			Outpoint:             buf.Bytes(),
			BatchKey:             batchKey,
		},
	)
	require.NoError(t, err)
}

// upsertChainTx inserts a transaction and returns its chain_txns id.
func upsertChainTx(t *testing.T, db *SqliteStore, tx *wire.MsgTx) int64 {
	t.Helper()

	raw, err := encodeTx(tx)
	require.NoError(t, err)
	txid := tx.TxHash()
	id, err := db.UpsertChainTx(context.Background(), sqlc.UpsertChainTxParams{
		Txid:  txid[:],
		RawTx: raw,
	})
	require.NoError(t, err)

	return id
}

// anchorGenesisTo points the genesis outpoint at a chain_txns row.
func anchorGenesisTo(t *testing.T, db *SqliteStore, genesis wire.OutPoint,
	chainID int64) {

	t.Helper()

	encoded, err := encodeOutpoint(genesis)
	require.NoError(t, err)
	err = db.AnchorGenesisPoint(
		context.Background(), sqlc.AnchorGenesisPointParams{
			PrevOut: encoded,
			AnchorTxID: sql.NullInt64{
				Int64: chainID,
				Valid: true,
			},
		},
	)
	require.NoError(t, err)
}

// TestRepairGenesisAnchor restores a retargeted anchor from the mint
// transaction still stored in chain_txns, leaves a genesis with no
// spender alone, and refuses to guess among several spenders.
func TestRepairGenesisAnchor(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	t.Run("restores mint spend", func(t *testing.T) {
		db := NewTestDB(t)
		genesis := asset.RandGenesis(t, asset.Normal)
		mintTx := customMintTx(t, genesis.FirstPrevOut)

		_, err := upsertAssetGen(
			ctx, db, genesis, nil,
			anchorProof(t, genesis, *mintTx),
		)
		require.NoError(t, err)
		mintID := genesisAnchorID(t, db, genesis.FirstPrevOut)

		bogus := wire.NewMsgTx(2)
		bogus.AddTxIn(&wire.TxIn{PreviousOutPoint: test.RandOp(t)})
		bogus.AddTxOut(&wire.TxOut{Value: 1, PkScript: []byte{0x51}})
		bogusID := upsertChainTx(t, db, bogus)
		anchorGenesisTo(t, db, genesis.FirstPrevOut, bogusID)
		require.Equal(t, bogusID, genesisAnchorID(
			t, db, genesis.FirstPrevOut,
		))

		require.NoError(t, repairGenesisAnchors(ctx, db))
		require.Equal(t, mintID, genesisAnchorID(
			t, db, genesis.FirstPrevOut,
		))

		require.NoError(t, repairGenesisAnchors(ctx, db))
		require.Equal(t, mintID, genesisAnchorID(
			t, db, genesis.FirstPrevOut,
		))
	})

	t.Run("no spender is left unchanged", func(t *testing.T) {
		db := NewTestDB(t)
		genesis := asset.RandGenesis(t, asset.Normal)
		encoded, err := encodeOutpoint(genesis.FirstPrevOut)
		require.NoError(t, err)
		_, err = db.UpsertGenesisPoint(ctx, encoded)
		require.NoError(t, err)

		bogus := wire.NewMsgTx(2)
		bogus.AddTxIn(&wire.TxIn{PreviousOutPoint: test.RandOp(t)})
		bogus.AddTxOut(&wire.TxOut{Value: 1, PkScript: []byte{0x51}})
		bogusID := upsertChainTx(t, db, bogus)
		anchorGenesisTo(t, db, genesis.FirstPrevOut, bogusID)

		require.NoError(t, repairGenesisAnchors(ctx, db))
		require.Equal(t, bogusID, genesisAnchorID(
			t, db, genesis.FirstPrevOut,
		))
	})

	t.Run("multiple spenders error", func(t *testing.T) {
		db := NewTestDB(t)
		genesis := asset.RandGenesis(t, asset.Normal)
		encoded, err := encodeOutpoint(genesis.FirstPrevOut)
		require.NoError(t, err)
		_, err = db.UpsertGenesisPoint(ctx, encoded)
		require.NoError(t, err)

		bogus := wire.NewMsgTx(2)
		bogus.AddTxIn(&wire.TxIn{PreviousOutPoint: test.RandOp(t)})
		bogus.AddTxOut(&wire.TxOut{Value: 1, PkScript: []byte{0x51}})
		bogusID := upsertChainTx(t, db, bogus)
		anchorGenesisTo(t, db, genesis.FirstPrevOut, bogusID)

		for i := 0; i < 2; i++ {
			spender := wire.NewMsgTx(2)
			spender.AddTxIn(&wire.TxIn{
				PreviousOutPoint: genesis.FirstPrevOut,
			})
			spender.AddTxOut(&wire.TxOut{
				Value:    int64(100 + i),
				PkScript: []byte{byte(i + 1)},
			})
			upsertChainTx(t, db, spender)
		}

		err = repairGenesisAnchors(ctx, db)
		require.Error(t, err)
		require.Equal(t, bogusID, genesisAnchorID(
			t, db, genesis.FirstPrevOut,
		))
	})
}

// signedCommitTx inserts a signed commitment that spends prevOut.
func signedCommitTx(t *testing.T, h *supplyCommitTestHarness,
	prevOut wire.OutPoint) {

	t.Helper()

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: prevOut})
	tx.AddTxOut(&wire.TxOut{Value: 1000, PkScript: []byte{0x51}})

	internalKey, _ := test.RandKeyDesc(t)
	err := h.commitMachine.InsertSignedCommitTx(
		h.ctx, h.assetSpec, supplycommit.SupplyCommitTxn{
			Txn:         tx,
			InternalKey: internalKey,
			OutputKey:   test.RandPubKey(t),
			OutputIndex: 0,
		},
	)
	require.NoError(t, err)
}

// TestAbandonInvalidUnconfirmedSupplyCommit drops a broadcast commitment
// that spends neither the mint pre-commit nor a confirmed commitment,
// and keeps the pending update. A commitment that spends the real
// pre-commit is left in CommitBroadcastState.
func TestAbandonInvalidUnconfirmedSupplyCommit(t *testing.T) {
	t.Parallel()

	t.Run("abandons unknown input", func(t *testing.T) {
		h := newSupplyCommitTestHarness(t)
		batchKey, _, mintTx, _, _ := h.addTestMintingBatch()
		_, _ = h.addTestMintAnchorUniCommitment(
			batchKey, sql.NullInt64{}, mintTx.TxHash(),
		)

		err := h.commitMachine.InsertPendingUpdate(
			h.ctx, h.assetSpec, h.randMintEvent(),
		)
		require.NoError(t, err)

		signedCommitTx(t, h, test.RandOp(t))
		h.assertCurrentStateIs(&supplycommit.CommitBroadcastState{})

		err = abandonInvalidUnconfirmedSupplyCommits(h.ctx, h.db)
		require.NoError(t, err)

		h.assertCurrentStateIs(&supplycommit.UpdatesPendingState{})
		transition := h.assertPendingTransitionExists()
		require.False(t, transition.NewCommitmentID.Valid)
		require.False(t, transition.PendingCommitTxnID.Valid)
		require.False(t, transition.Frozen)

		fetched := h.currentTransition().UnwrapOrFail(t)
		require.Nil(t, fetched.NewCommitment.Txn)
		require.Len(t, fetched.PendingUpdates, 1)

		left, err := h.db.FetchUnconfirmedBroadcastSupplyCommits(
			h.ctx,
		)
		require.NoError(t, err)
		require.Empty(t, left)
	})

	t.Run("keeps pre-commit spend", func(t *testing.T) {
		h := newSupplyCommitTestHarness(t)
		batchKey, _, mintTx, _, _ := h.addTestMintingBatch()
		_, preOut := h.addTestMintAnchorUniCommitment(
			batchKey, sql.NullInt64{}, mintTx.TxHash(),
		)

		err := h.commitMachine.InsertPendingUpdate(
			h.ctx, h.assetSpec, h.randMintEvent(),
		)
		require.NoError(t, err)

		signedCommitTx(t, h, preOut)
		err = abandonInvalidUnconfirmedSupplyCommits(h.ctx, h.db)
		require.NoError(t, err)

		h.assertCurrentStateIs(&supplycommit.CommitBroadcastState{})
		transition := h.assertPendingTransitionExists()
		require.True(t, transition.NewCommitmentID.Valid)
	})
}

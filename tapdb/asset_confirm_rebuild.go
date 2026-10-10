package tapdb

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/tapfreighter"
)

// outbound parcel using the given transaction-scoped query set. This
// is the porter site's phase-1 write: it commits atomically with the
// anchoring registration itself.
func (a *AssetStore) ApplyPendingParcel(ctx context.Context,
	q *sqlc.Queries, spend *tapfreighter.OutboundParcel,
	finalLeaseOwner [32]byte, finalLeaseExpiry time.Time) error {

	return a.applyPendingParcel(
		ctx, q, spend, finalLeaseOwner, finalLeaseExpiry,
	)
}
// applyPendingParcel stakes an outbound parcel within the caller's
// transaction: the transfer row, its inputs and outputs, and the
// input leases.
func (a *AssetStore) applyPendingParcel(ctx context.Context,
	q ActiveAssetsStore, spend *tapfreighter.OutboundParcel,
	finalLeaseOwner [32]byte, finalLeaseExpiry time.Time) error {

	newAnchorTXID := spend.AnchorTx.TxHash()

	// A retry of the same anchor (a lost PublishAndLogTransfer
	// response, or a second porter entry for that anchor) must not
	// insert another asset_transfers row. chain_txns.txid is unique,
	// but asset_transfers.anchor_txn_id is not.
	existing, err := q.QueryAssetTransfers(ctx, TransferQuery{
		AnchorTxHash: newAnchorTXID[:],
	})
	if err != nil {
		return fmt.Errorf("unable to query existing transfer: %w",
			err)
	}
	if len(existing) > 0 {
		log.Infof("Anchor transaction %v already logged as "+
			"transfer id=%d; not inserting another row",
			newAnchorTXID, existing[0].ID)

		return nil
	}

	anchorTxBytes, err := fn.Serialize(spend.AnchorTx)
	if err != nil {
		return err
	}

	// First, we'll insert the new transaction that anchors the new
	// anchor point (commits to the set of new outputs).
	txnID, err := q.UpsertChainTx(ctx, ChainTxParams{
		Txid:      newAnchorTXID[:],
		RawTx:     anchorTxBytes,
		ChainFees: spend.ChainFees,
	})
	if err != nil {
		return fmt.Errorf("unable to insert new chain tx: %w", err)
	}

	// The transfer itself is just a shell which the inputs and
	// outputs will reference. We'll insert this next, so we can use
	// its ID.
	transferID, err := q.InsertAssetTransfer(ctx, NewAssetTransfer{
		HeightHint:            int32(spend.AnchorTxHeightHint),
		AnchorTxid:            newAnchorTXID[:],
		TransferTimeUnix:      spend.TransferTime,
		Label:                 sqlStr(spend.Label),
		SkipAnchorTxBroadcast: spend.SkipAnchorTxBroadcast,
	})
	if err != nil {
		return fmt.Errorf("unable to insert asset transfer: %w", err)
	}

	// Next, we'll insert the inputs to this transfer.
	for idx := range spend.Inputs {
		err := insertAssetTransferInput(
			ctx, q, transferID, spend.Inputs[idx],
			finalLeaseOwner, finalLeaseExpiry,
		)
		if err != nil {
			return fmt.Errorf("unable to insert asset transfer "+
				"input: %w", err)
		}
	}

	// Also extend leases for any zero-value UTXOs being swept.
	for _, zeroValueInput := range spend.ZeroValueInputs {
		outpointBytes, err := encodeOutpoint(zeroValueInput.OutPoint)
		if err != nil {
			return fmt.Errorf("unable to encode zero-value "+
				"outpoint: %w", err)
		}

		err = q.UpdateUTXOLease(ctx, UpdateUTXOLease{
			LeaseOwner:  finalLeaseOwner[:],
			LeaseExpiry: sqlTime(finalLeaseExpiry.UTC()),
			Outpoint:    outpointBytes,
		})
		if err != nil {
			return fmt.Errorf("unable to extend zero-value "+
				"UTXO lease: %w", err)
		}
	}

	// Then the passive assets.
	if len(spend.PassiveAssets) > 0 {
		if spend.PassiveAssetsAnchor == nil {
			return fmt.Errorf("passive assets anchor is required")
		}

		err = insertPassiveAssets(
			ctx, q, transferID, txnID, spend.PassiveAssetsAnchor,
			spend.PassiveAssets,
		)
		if err != nil {
			return fmt.Errorf("unable to insert passive "+
				"assets: %w", err)
		}
	}

	// And then finally the outputs.
	for idx := range spend.Outputs {
		err = insertAssetTransferOutput(
			ctx, q, transferID, txnID, spend.Outputs[idx],
		)
		if err != nil {
			return fmt.Errorf("unable to insert asset transfer "+
				"output: %w", err)
		}
	}

	return nil
}

func (a *AssetStore) rebuildAnchorConfirm(ctx context.Context,
	q ActiveAssetsStore, anchorTx *wire.MsgTx, blockHash chainhash.Hash,
	blockHeight, txIndex uint32, header wire.BlockHeader,
	merkle proof.TxMerkleProof,
	burnNote string) (*tapfreighter.AssetConfirmEvent,
	[]*tapfreighter.AssetBurn, error) {

	anchorTxid := anchorTx.TxHash()

	assetTransfers, err := q.QueryAssetTransfers(ctx, TransferQuery{
		AnchorTxHash: anchorTxid[:],
	})
	if err != nil {
		return nil, nil, fmt.Errorf("unable to query asset "+
			"transfers: %w", err)
	}
	if len(assetTransfers) == 0 {
		return nil, nil, fmt.Errorf("no transfer found for anchor "+
			"tx %v", anchorTxid)
	}
	assetTransfer := assetTransfers[0]

	inputs, err := q.FetchTransferInputs(ctx, assetTransfer.ID)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to fetch transfer "+
			"inputs: %w", err)
	}
	outputs, err := q.FetchTransferOutputs(ctx, assetTransfer.ID)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to fetch transfer "+
			"outputs: %w", err)
	}

	// Decode the transfer's inputs into their previous IDs. Each
	// output picks out its own inputs from these below, by witness
	// reference: an anchor transaction can carry several independent
	// same-asset transitions (aggregated sweeps), so grouping by
	// asset ID alone would staple a suffix onto an unrelated input's
	// file.
	inputPrevIDs := make([]asset.PrevID, 0, len(inputs))
	for idx := range inputs {
		in := inputs[idx]

		var op wire.OutPoint
		err := readOutPoint(
			bytes.NewReader(in.AnchorPoint), 0, 0, &op,
		)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to decode "+
				"input anchor point: %w", err)
		}

		var assetID asset.ID
		copy(assetID[:], in.AssetID)

		var scriptKey asset.SerializedKey
		copy(scriptKey[:], in.ScriptKey)

		inputPrevIDs = append(inputPrevIDs, asset.PrevID{
			OutPoint:  op,
			ID:        assetID,
			ScriptKey: scriptKey,
		})
	}

	// Rebuild the zero-value sweep set. The live confirmation event
	// carries the funding step's selection out of porter memory; the
	// rebuilt event must derive the same set, or the confirmation
	// application never marks the swept anchors and coin selection
	// can fund a later transfer with an outpoint this transaction
	// already spent, once the sweep lease expires. The set is
	// recoverable from stored state: a zero-value sweep is an
	// anchor-transaction input that carries a managed-UTXO row but
	// is not one of the transfer's asset inputs (wallet-funded fee
	// inputs have no managed row). Only the outpoint is rebuilt —
	// it is all the confirmation application consumes; the remaining
	// fields serve funding-time signing.
	inputAnchors := make(map[wire.OutPoint]struct{}, len(inputPrevIDs))
	for _, prevID := range inputPrevIDs {
		inputAnchors[prevID.OutPoint] = struct{}{}
	}

	var zeroValueInputs []*tapfreighter.ZeroValueInput
	for _, txIn := range anchorTx.TxIn {
		op := txIn.PreviousOutPoint
		if _, ok := inputAnchors[op]; ok {
			continue
		}

		outpointBytes, err := encodeOutpoint(op)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to encode "+
				"anchor input outpoint: %w", err)
		}

		_, err = q.FetchManagedUTXO(ctx, UtxoQuery{
			Outpoint: outpointBytes,
		})
		switch {
		case errors.Is(err, sql.ErrNoRows):
			continue

		case err != nil:
			return nil, nil, fmt.Errorf("unable to look up "+
				"managed UTXO for anchor input %v: %w", op,
				err)
		}

		zeroValueInputs = append(
			zeroValueInputs, &tapfreighter.ZeroValueInput{
				OutPoint: op,
			},
		)
	}

	// fetchInputFile loads an input's full proof file from the
	// database by its previous ID.
	fetchInputFile := func(prevID asset.PrevID) (*proof.File, error) {
		outpointBytes, err := encodeOutpoint(prevID.OutPoint)
		if err != nil {
			return nil, err
		}

		rows, err := q.FetchAssetProof(
			ctx, sqlc.FetchAssetProofParams{
				TweakedScriptKey: prevID.ScriptKey[:],
				Outpoint:         outpointBytes,
				AssetID:          prevID.ID[:],
			},
		)
		if err != nil {
			return nil, fmt.Errorf("unable to fetch input "+
				"proof: %w", err)
		}
		if len(rows) == 0 {
			return nil, fmt.Errorf("no input proof for %v",
				prevID.OutPoint)
		}

		file := &proof.File{}
		err = file.Decode(bytes.NewReader(rows[0].ProofFile))
		if err != nil {
			return nil, fmt.Errorf("unable to decode input "+
				"proof file: %w", err)
		}

		return file, nil
	}

	var (
		finalProofs = make(
			map[tapfreighter.OutputIdentifier]*proof.AnnotatedProof,
			len(outputs),
		)
		burns []*tapfreighter.AssetBurn
	)
	for idx := range outputs {
		out := outputs[idx]
		if len(out.ProofSuffix) == 0 {
			continue
		}

		suffix := &proof.Proof{}
		err := suffix.Decode(bytes.NewReader(out.ProofSuffix))
		if err != nil {
			return nil, nil, fmt.Errorf("unable to decode "+
				"proof suffix: %w", err)
		}

		// Stamp the witness's block context onto the suffix; this
		// is exactly what confirmation adds to the pre-broadcast
		// suffix.
		suffix.AnchorTx = *anchorTx
		suffix.BlockHeader = header
		suffix.BlockHeight = blockHeight
		suffix.TxMerkleProof = merkle

		// The output's full proof file is its primary input's
		// file with the suffix appended, and any additional
		// inputs' files attached to the suffix. Which inputs
		// those are is determined by the suffix's own witnesses
		// (resolved through the split commitment root where
		// applicable), exactly as at pre-broadcast verification.
		assetID := suffix.Asset.ID()
		witnesses := suffix.Asset.Witnesses()
		var prevIDs []asset.PrevID
		for _, in := range inputPrevIDs {
			for _, witness := range witnesses {
				if witness.PrevID != nil &&
					in == *witness.PrevID {

					prevIDs = append(prevIDs, in)
				}
			}
		}
		if len(prevIDs) == 0 {
			return nil, nil, fmt.Errorf("no inputs found for "+
				"output asset %v", assetID)
		}

		// Burn leaves are verified without a prior snapshot, so
		// they need every input file, including the primary.
		// Collected here, before the primary file is extended
		// with this suffix, and not written onto the suffix the
		// transfer proof file stores.
		var burnInputs map[asset.PrevID]*proof.File
		if suffix.Asset.IsBurn() {
			burnInputs = make(
				map[asset.PrevID]*proof.File, len(prevIDs),
			)
		}

		for extra := 1; extra < len(prevIDs); extra++ {
			extraFile, err := fetchInputFile(prevIDs[extra])
			if err != nil {
				return nil, nil, err
			}
			if burnInputs != nil {
				_, seen := burnInputs[prevIDs[extra]]
				if !seen {
					burnInputs[prevIDs[extra]] = extraFile
				}
			}
			suffix.AdditionalInputs = append(
				suffix.AdditionalInputs, *extraFile,
			)
		}

		file, err := fetchInputFile(prevIDs[0])
		if err != nil {
			return nil, nil, err
		}
		if burnInputs != nil {
			cloned, err := tapfreighter.CloneProofFile(file)
			if err != nil {
				return nil, nil, fmt.Errorf("unable to copy "+
					"burn input proof: %w", err)
			}
			burnInputs[prevIDs[0]] = cloned
		}
		if err := file.AppendProof(*suffix); err != nil {
			return nil, nil, fmt.Errorf("unable to append "+
				"proof: %w", err)
		}
		var blob bytes.Buffer
		if err := file.Encode(&blob); err != nil {
			return nil, nil, fmt.Errorf("unable to encode "+
				"proof file: %w", err)
		}

		fullScriptKey, err := parseScriptKey(
			out.InternalKey, out.ScriptKey,
		)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to decode "+
				"script key: %w", err)
		}
		scriptPubKey := fullScriptKey.PubKey

		outKey := tapfreighter.NewOutputIdentifier(
			assetID, suffix.InclusionProof.OutputIndex,
			*scriptPubKey,
		)
		finalProofs[outKey] = &proof.AnnotatedProof{
			Locator: proof.Locator{
				AssetID:   &assetID,
				ScriptKey: *scriptPubKey,
				OutPoint:  fn.Ptr(suffix.OutPoint()),
			},
			Blob: blob.Bytes(),
		}

		// Burns are recognizable from the suffix itself. The
		// leaf proof is a copy that embeds input provenance;
		// the suffix stored in the transfer proof file is left
		// as the chain built above.
		if suffix.Asset.IsBurn() {
			burnProof, err := tapfreighter.BurnLeafProof(suffix, burnInputs)
			if err != nil {
				return nil, nil, fmt.Errorf("unable to "+
					"build burn proof: %w", err)
			}

			burn := &tapfreighter.AssetBurn{
				Note:      burnNote,
				AssetID:   assetID[:],
				AssetType: suffix.Asset.Type,
				Amount:    uint64(out.Amount),
				//nolint:lll
				AnchorTxid: anchorTxid,
				ScriptKey:  &suffix.Asset.ScriptKey,
				Proof:      burnProof,
				OutPoint: wire.OutPoint{
					Hash: anchorTxid,
					//nolint:lll
					Index: suffix.InclusionProof.OutputIndex,
				},
			}
			if suffix.Asset.GroupKey != nil {
				groupKey := suffix.Asset.GroupKey.GroupPubKey
				burn.GroupKey = groupKey.
					SerializeCompressed()
			}

			burns = append(burns, burn)
		}
	}

	passiveFiles := make(map[asset.ID][]*proof.AnnotatedProof)

	conf := &tapfreighter.AssetConfirmEvent{
		AnchorTXID:             anchorTxid,
		BlockHash:              blockHash,
		BlockHeight:            int32(blockHeight),
		TxIndex:                int32(txIndex),
		FinalProofs:            finalProofs,
		PassiveAssetProofFiles: passiveFiles,
		ZeroValueInputs:        zeroValueInputs,
	}

	return conf, burns, nil
}

// RebuildConfirmEvent is RebuildAnchorConfirm inside a read
// transaction of its own, for callers outside the watcher's delivery
// path (the porter's proof-file mirroring and burn-event dispatch).
func (a *AssetStore) RebuildConfirmEvent(ctx context.Context,
	anchorTx *wire.MsgTx, blockHash chainhash.Hash,
	blockHeight, txIndex uint32, header wire.BlockHeader,
	merkle proof.TxMerkleProof,
	burnNote string) (*tapfreighter.AssetConfirmEvent,
	[]*tapfreighter.AssetBurn, error) {

	var (
		conf  *tapfreighter.AssetConfirmEvent
		burns []*tapfreighter.AssetBurn
	)
	readOpts := NewAssetStoreReadTx()
	dbErr := a.db.ExecTx(ctx, &readOpts, func(q ActiveAssetsStore) error {
		var err error
		conf, burns, err = a.rebuildAnchorConfirm(
			ctx, q, anchorTx, blockHash, blockHeight, txIndex,
			header, merkle, burnNote,
		)

		return err
	})
	if dbErr != nil {
		return nil, nil, dbErr
	}

	return conf, burns, nil
}

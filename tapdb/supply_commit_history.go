package tapdb

import (
	"bytes"
	"context"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/universe/supplycommit"
	"github.com/lightninglabs/taproot-assets/universe/supplyverifier"
)

// FetchCommitmentPushData loads everything the push dispatcher needs
// about a finalized commitment from the durable record: the root
// commitment (with its chain-transaction context), the update events
// the finalized transition committed, and the chain proof written at
// finalization.
func (s *SupplyCommitMachine) FetchCommitmentPushData(ctx context.Context,
	groupKey *btcec.PublicKey, commitTxid chainhash.Hash) (
	supplycommit.RootCommitment, []supplycommit.SupplyUpdateEvent,
	supplycommit.ChainProof, error) {

	var (
		groupKeyBytes = schnorr.SerializePubKey(groupKey)
		commitment    supplycommit.RootCommitment
		updates       []supplycommit.SupplyUpdateEvent
		chainProof    supplycommit.ChainProof
	)

	readTx := ReadTxOption()
	err := s.db.ExecTx(ctx, readTx, func(db SupplyCommitStore) error {
		commitRow, err := db.QuerySupplyCommitmentByTxid(
			ctx, sqlc.QuerySupplyCommitmentByTxidParams{
				GroupKey: groupKeyBytes,
				Txid:     commitTxid[:],
			},
		)
		if err != nil {
			return fmt.Errorf("unable to query commitment for "+
				"tx %v: %w", commitTxid, err)
		}

		commitOpt, err := fetchCommitment(
			ctx, db, sqlInt64(commitRow.SupplyCommitment.CommitID),
		)
		if err != nil {
			return fmt.Errorf("unable to fetch commitment: %w",
				err)
		}
		commit, err := commitOpt.UnwrapOrErr(
			fmt.Errorf("commitment %d vanished mid-transaction",
				commitRow.SupplyCommitment.CommitID),
		)
		if err != nil {
			return err
		}
		commitment = commit

		var haveProof bool
		commitment.CommitmentBlock.WhenSome(
			func(b supplycommit.CommitmentBlock) {
				if b.BlockHeader == nil ||
					b.MerkleProof == nil {

					return
				}
				chainProof = supplycommit.ChainProof{
					Header:      *b.BlockHeader,
					BlockHeight: b.Height,
					MerkleProof: *b.MerkleProof,
					TxIndex:     b.TxIndex,
				}
				haveProof = true
			},
		)
		if !haveProof {
			return fmt.Errorf("commitment %v has no chain proof",
				commitTxid)
		}

		transitionRow, err :=
			db.QuerySupplyCommitTransitionByNewCommitment(
				ctx, sqlInt64(commitRow.SupplyCommitment.CommitID),
			)
		if err != nil {
			return fmt.Errorf("unable to query transition for "+
				"commitment %d: %w",
				commitRow.SupplyCommitment.CommitID, err)
		}
		dbTransition := transitionRow.SupplyCommitTransition

		eventRows, err := db.QuerySupplyUpdateEvents(
			ctx, sqlInt64(dbTransition.TransitionID),
		)
		if err != nil {
			return fmt.Errorf("unable to query update events: "+
				"%w", err)
		}
		updates = make(
			[]supplycommit.SupplyUpdateEvent, 0, len(eventRows),
		)
		for _, eventRow := range eventRows {
			event, err := deserializeSupplyUpdateEvent(
				eventRow.UpdateTypeName,
				bytes.NewReader(eventRow.EventData),
			)
			if err != nil {
				return fmt.Errorf("unable to deserialize "+
					"update event: %w", err)
			}
			updates = append(updates, event)
		}

		return nil
	})
	if err != nil {
		return commitment, nil, chainProof, err
	}

	return commitment, updates, chainProof, nil
}

// FetchSupplyCommitPush loads the push payload for the supply
// commitment that created outpoint. The syncer uses it to insert a
// predecessor the remote universe has not seen.
func (s *SupplyCommitMachine) FetchSupplyCommitPush(ctx context.Context,
	assetSpec asset.Specifier, outpoint wire.OutPoint) (
	supplycommit.RootCommitment, supplycommit.SupplyLeaves,
	supplycommit.ChainProof, error) {

	var (
		zeroCommit supplycommit.RootCommitment
		zeroLeaves supplycommit.SupplyLeaves
		zeroProof  supplycommit.ChainProof
	)

	groupKey, err := assetSpec.UnwrapGroupKeyOrErr()
	if err != nil {
		return zeroCommit, zeroLeaves, zeroProof, fmt.Errorf(
			"asset specifier missing group key: %w", err)
	}

	commitment, updates, chainProof, err := s.FetchCommitmentPushData(
		ctx, groupKey, outpoint.Hash,
	)
	if err != nil {
		return zeroCommit, zeroLeaves, zeroProof, err
	}

	if commitment.TxOutIdx != outpoint.Index {
		return zeroCommit, zeroLeaves, zeroProof, fmt.Errorf(
			"supply commitment %v is at output %d, not %d",
			outpoint.Hash, commitment.TxOutIdx, outpoint.Index)
	}

	leaves, err := supplycommit.NewSupplyLeavesFromEvents(updates)
	if err != nil {
		return zeroCommit, zeroLeaves, zeroProof, err
	}

	return commitment, leaves, chainProof, nil
}

var _ supplyverifier.SupplyCommitHistory = (*SupplyCommitMachine)(nil)

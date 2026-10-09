package supplycommit

import (
	"context"
	"fmt"

	"github.com/lightninglabs/taproot-assets/proof"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
)

// commitBurialDepth returns the confirmation depth at which a supply
// commitment is buried and may be finalized.
func commitBurialDepth(env *Environment) uint32 {
	if env.CommitConfTarget == 0 {
		return DefaultCommitConfTarget
	}

	return env.CommitConfTarget
}

// isCommitBuried returns true when the chain tip is deep enough for the
// commitment transaction at confHeight to be considered buried.
func isCommitBuried(tipHeight, confHeight uint32, burialDepth uint32) bool {
	if burialDepth == 0 {
		return false
	}

	// The transaction has burialDepth confirmations when the tip is at
	// least confHeight + burialDepth - 1.
	return tipHeight+1 >= confHeight+burialDepth
}

// applyConfToTransition attaches chain proof data from a confirmation event
// to the pending supply transition.
func applyConfToTransition(transition SupplyStateTransition,
	conf *ConfEvent) (SupplyStateTransition, error) {

	merkleProof, err := proof.NewTxMerkleProof(
		conf.Block.Transactions, int(conf.TxIndex),
	)
	if err != nil {
		return transition, fmt.Errorf("unable to create merkle "+
			"proof: %w", err)
	}

	transition.ChainProof = lfn.Some(ChainProof{
		Header:      conf.Block.Header,
		BlockHeight: conf.BlockHeight,
		MerkleProof: *merkleProof,
		TxIndex:     conf.TxIndex,
	})

	return transition, nil
}

// transitionToCommitFinalize persists and returns the state transition that
// hands off to CommitFinalizeState for universe push and tree updates.
func transitionToCommitFinalize(ctx context.Context, env *Environment,
	transition SupplyStateTransition) (*StateTransition, error) {

	err := env.StateLog.CommitState(
		ctx, env.AssetSpec, &CommitFinalizeState{},
	)
	if err != nil {
		return nil, fmt.Errorf("unable to commit state transition: %w",
			err)
	}

	return &StateTransition{
		NextState: &CommitFinalizeState{
			SupplyTransition: transition,
		},
		NewEvents: lfn.Some(FsmEvent{
			InternalEvent: []Event{&FinalizeEvent{}},
		}),
	}, nil
}

// transitionForBuriedConf builds the finalize transition once a commitment
// transaction is buried on chain.
func transitionForBuriedConf(ctx context.Context, env *Environment,
	transition SupplyStateTransition, conf *ConfEvent) (*StateTransition,
	error) {

	transition, err := applyConfToTransition(transition, conf)
	if err != nil {
		return nil, err
	}

	return transitionToCommitFinalize(ctx, env, transition)
}

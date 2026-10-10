package supplycommit

import (
	"context"
	"errors"
	"testing"

	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestTransitionForBuriedConfEntersFinalizeState pins review item 2: a buried
// confirmation must hand off to CommitFinalizeState (universe push / tree
// finalize), not before burial depth is met (see TestIsCommitBuried).
func TestTransitionForBuriedConfEntersFinalizeState(t *testing.T) {
	ctx := context.Background()

	header := wire.BlockHeader{}
	block := wire.NewMsgBlock(&header)
	commitTx := wire.NewMsgTx(2)
	commitTx.AddTxOut(&wire.TxOut{Value: 1000, PkScript: []byte{0x51}})
	block.AddTransaction(commitTx)

	conf := &ConfEvent{
		BlockHeight: 10,
		Block:       block,
		TxIndex:     0,
	}

	transition := SupplyStateTransition{
		NewCommitment: RootCommitment{Txn: commitTx},
	}

	groupKey := test.RandPubKey(t)
	spec := asset.NewSpecifierFromGroupKey(*groupKey)

	stateLog := &mockStateMachineStore{}
	stateLog.On(
		"CommitState", mock.Anything, spec, mock.Anything,
	).Return(nil)

	env := &Environment{
		StateLog:  stateLog,
		AssetSpec: spec,
	}

	result, err := transitionForBuriedConf(ctx, env, transition, conf)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.IsType(t, &CommitFinalizeState{}, result.NextState)

	finalizeState, ok := result.NextState.(*CommitFinalizeState)
	require.True(t, ok)
	require.True(t, finalizeState.SupplyTransition.ChainProof.IsSome())

	events, err := result.NewEvents.UnwrapOrErr(
		errors.New("missing emitted events"),
	)
	require.NoError(t, err)
	require.Len(t, events.InternalEvent, 1)
	require.IsType(t, &FinalizeEvent{}, events.InternalEvent[0])
}

package supplycommit

import (
	"context"
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/stretchr/testify/require"
)

func TestFindCommitConfirmation(t *testing.T) {
	commitTx := wire.NewMsgTx(2)
	commitTx.AddTxOut(&wire.TxOut{Value: 1000, PkScript: []byte{0x51}})

	header := wire.BlockHeader{}
	block := wire.NewMsgBlock(&header)
	block.AddTransaction(wire.NewMsgTx(2))
	block.AddTransaction(commitTx)

	chain := tapgarden.NewMockChainBridge()
	chain.BlocksByHeight = map[int64]*wire.MsgBlock{}
	for height := int64(1); height <= 5; height++ {
		if height == 5 {
			chain.BlocksByHeight[height] = block
			continue
		}

		empty := wire.NewMsgBlock(&header)
		chain.BlocksByHeight[height] = empty
	}
	chain.TipHeight = 5

	conf, err := findCommitConfirmation(
		context.Background(), chain, commitTx,
	)
	require.NoError(t, err)
	confEvent, err := conf.UnwrapOrErr(fmt.Errorf("missing"))
	require.NoError(t, err)
	require.Equal(t, uint32(5), confEvent.BlockHeight)

	otherTx := wire.NewMsgTx(2)
	otherTx.AddTxOut(&wire.TxOut{Value: 1, PkScript: []byte{0x52}})

	missing, err := findCommitConfirmation(
		context.Background(), chain, otherTx,
	)
	require.NoError(t, err)
	require.False(t, missing.IsSome())

	delete(chain.BlocksByHeight, 5)
	_, err = findCommitConfirmation(
		context.Background(), chain, commitTx,
	)
	require.Error(t, err)
}

func TestIsCommitBuried(t *testing.T) {
	depth := uint32(DefaultCommitConfTarget)

	require.False(t, isCommitBuried(12, 10, depth))
	require.True(t, isCommitBuried(15, 10, depth))
}

func TestTryRecoverBuriedBroadcastNotBuried(t *testing.T) {
	commitTx := wire.NewMsgTx(2)
	commitTx.AddTxOut(&wire.TxOut{Value: 1000, PkScript: []byte{0x51}})

	header := wire.BlockHeader{}
	block := wire.NewMsgBlock(&header)
	block.AddTransaction(commitTx)

	chain := tapgarden.NewMockChainBridge()
	chain.BlocksByHeight = map[int64]*wire.MsgBlock{}
	for height := int64(1); height <= 12; height++ {
		if height == 10 {
			chain.BlocksByHeight[height] = block
			continue
		}
		chain.BlocksByHeight[height] = wire.NewMsgBlock(&header)
	}
	chain.TipHeight = 12

	env := &Environment{
		Chain:            chain,
		CommitConfTarget: DefaultCommitConfTarget,
	}

	state := &CommitBroadcastState{
		SupplyTransition: SupplyStateTransition{
			NewCommitment: RootCommitment{Txn: commitTx},
		},
	}

	transition, recovered, err := tryRecoverBuriedBroadcast(
		context.Background(), state, env,
	)
	require.NoError(t, err)
	require.False(t, recovered)
	require.Nil(t, transition)
}

func TestTryRecoverBuriedBroadcastReorgBeforeBurial(t *testing.T) {
	commitTx := wire.NewMsgTx(2)
	commitTx.AddTxOut(&wire.TxOut{Value: 1000, PkScript: []byte{0x51}})

	header := wire.BlockHeader{}

	chain := tapgarden.NewMockChainBridge()
	chain.BlocksByHeight = map[int64]*wire.MsgBlock{}
	for height := int64(1); height <= 20; height++ {
		chain.BlocksByHeight[height] = wire.NewMsgBlock(&header)
	}
	// Commitment was seen at height 10 but re-orged away before burial.
	chain.TipHeight = 20

	env := &Environment{
		Chain:            chain,
		CommitConfTarget: DefaultCommitConfTarget,
	}
	state := &CommitBroadcastState{
		SupplyTransition: SupplyStateTransition{
			NewCommitment: RootCommitment{Txn: commitTx},
		},
	}

	transition, recovered, err := tryRecoverBuriedBroadcast(
		context.Background(), state, env,
	)
	require.NoError(t, err)
	require.False(t, recovered)
	require.Nil(t, transition)
}

func TestTryRecoverBuriedBroadcastScanError(t *testing.T) {
	commitTx := wire.NewMsgTx(2)
	commitTx.AddTxOut(&wire.TxOut{Value: 1000, PkScript: []byte{0x51}})

	chain := tapgarden.NewMockChainBridge()
	chain.TipHeight = 5
	chain.BlocksByHeight = map[int64]*wire.MsgBlock{}

	env := &Environment{Chain: chain}
	state := &CommitBroadcastState{
		SupplyTransition: SupplyStateTransition{
			NewCommitment: RootCommitment{Txn: commitTx},
		},
	}

	_, _, err := tryRecoverBuriedBroadcast(
		context.Background(), state, env,
	)
	require.Error(t, err)
}

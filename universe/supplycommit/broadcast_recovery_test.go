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
}

package supplycommit

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/tapgarden"
)

const (
	// maxCommitConfLookback limits how far back we scan for a commitment
	// transaction that confirmed while tapd was down.
	maxCommitConfLookback = 512
)

// findCommitConfirmation scans recent chain history for a commitment
// transaction. This covers restarts that miss the RegisterConf notification
// because the transaction confirmed while the daemon was stopped.
func findCommitConfirmation(ctx context.Context,
	chain tapgarden.ChainBridge, commitTx *wire.MsgTx) (fn.Option[*ConfEvent],
	error) {

	if commitTx == nil {
		return fn.None[*ConfEvent](), nil
	}

	txid := commitTx.TxHash()
	tip, err := chain.CurrentHeight(ctx)
	if err != nil {
		return fn.None[*ConfEvent](), fmt.Errorf("unable to get chain "+
			"tip: %w", err)
	}

	start := uint32(1)
	if tip > maxCommitConfLookback {
		start = tip - maxCommitConfLookback + 1
	}

	for height := tip; height >= start; height-- {
		block, err := chain.GetBlockByHeight(ctx, int64(height))
		if err != nil {
			return fn.None[*ConfEvent](), fmt.Errorf(
				"unable to fetch block %d: %w", height, err,
			)
		}

		for idx, blockTx := range block.Transactions {
			if blockTx.TxHash() != txid {
				continue
			}

			return fn.Some(&ConfEvent{
				Tx:          blockTx,
				TxIndex:     uint32(idx),
				BlockHeight: height,
				Block:       block,
			}), nil
		}
	}

	return fn.None[*ConfEvent](), nil
}

// tryRecoverBuriedBroadcast finalizes an in-flight broadcast when its
// commitment transaction is already buried on chain.
func tryRecoverBuriedBroadcast(ctx context.Context,
	c *CommitBroadcastState, env *Environment) (*StateTransition, bool,
	error) {

	commitTx := c.SupplyTransition.NewCommitment.Txn
	if commitTx == nil {
		return nil, false, nil
	}

	confOpt, err := findCommitConfirmation(ctx, env.Chain, commitTx)
	if err != nil {
		return nil, false, err
	}
	if confOpt.IsNone() {
		return nil, false, nil
	}
	conf, err := confOpt.UnwrapOrErr(fmt.Errorf("missing confirmation"))
	if err != nil {
		return nil, false, nil
	}

	tip, err := env.Chain.CurrentHeight(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("unable to get chain tip: %w", err)
	}

	burialDepth := commitBurialDepth(env)
	if !isCommitBuried(tip, conf.BlockHeight, burialDepth) {
		return nil, false, nil
	}

	transition, err := transitionForBuriedConf(
		ctx, env, c.SupplyTransition, conf,
	)
	if err != nil {
		return nil, false, err
	}

	return transition, true, nil
}

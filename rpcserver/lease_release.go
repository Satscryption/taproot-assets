package rpcserver

import (
	"context"

	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
)

// outputReleaser is the subset of the lnd wallet kit used to release leased
// outputs.
type outputReleaser interface {
	// ReleaseOutput unlocks an output, allowing it to be available for coin
	// selection if it remains unspent.
	ReleaseOutput(ctx context.Context, lockID wtxmgr.LockID,
		op wire.OutPoint) error
}

// releaseLeasedOutputs releases the given lnd wallet leases. It is meant to be
// called from deferred cleanup paths, which commonly run because the request
// context was canceled (client deadline, disconnect). Releasing on that
// context would fail immediately and leak the leases until they expire, so the
// release runs on a context that keeps the values of the parent but not its
// cancellation, bounded by leaseReleaseTimeout. See
// lightninglabs/taproot-assets#2206.
func releaseLeasedOutputs(parent context.Context, wallet outputReleaser,
	leases []*walletrpc.UtxoLease, outpoints []wire.OutPoint) {

	ctx, cancel := context.WithTimeout(
		context.WithoutCancel(parent), leaseReleaseTimeout,
	)
	defer cancel()

	for idx, lease := range leases {
		var lockID wtxmgr.LockID
		copy(lockID[:], lease.Id)

		op := outpoints[idx]
		err := wallet.ReleaseOutput(ctx, lockID, op)
		if err != nil {
			rpcsLog.Errorf("Error unlocking lnd UTXO %v: %v", op,
				err)
		}
	}
}

package rpcserver

import (
	"context"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/tapconfig"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	wrpc "github.com/lightninglabs/taproot-assets/taprpc/assetwalletrpc"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
	"github.com/stretchr/testify/require"
)

// driftFundWallet returns a funded anchor that drifts from the template and
// records each ReleaseOutput together with the context it was called on.
type driftFundWallet struct {
	lndclient.WalletKitClient

	funded *psbt.Packet
	change int32
	leases []*walletrpc.UtxoLease

	fundReq  *walletrpc.FundPsbtRequest
	releases *mockReleaser
}

// FundPsbt returns the drifted packet and the leases lnd would have taken.
// The request context is ignored so a canceled RPC still observes a successful
// fund, which is the window the deferred release has to clean up.
func (w *driftFundWallet) FundPsbt(_ context.Context,
	req *walletrpc.FundPsbtRequest) (*psbt.Packet, int32,
	[]*walletrpc.UtxoLease, error) {

	w.fundReq = req

	return w.funded, w.change, w.leases, nil
}

// ReleaseOutput records the release context and fails when that context is
// already done, matching lnd.
func (w *driftFundWallet) ReleaseOutput(ctx context.Context,
	lockID wtxmgr.LockID, op wire.OutPoint) error {

	return w.releases.ReleaseOutput(ctx, lockID, op)
}

// driftedLeases builds n wallet leases with distinct ids and outpoints.
func driftedLeases(n int) []*walletrpc.UtxoLease {
	leases := make([]*walletrpc.UtxoLease, n)
	for i := 0; i < n; i++ {
		leases[i] = &walletrpc.UtxoLease{
			Id: []byte{byte(i + 1)},
			Outpoint: &lnrpc.OutPoint{
				TxidBytes:   []byte{byte(0xa0 + i)},
				OutputIndex: uint32(i),
			},
		}
	}

	return leases
}

// leaseOutpoint is the outpoint CommitVirtualPsbts derives from a lease.
func leaseOutpoint(lease *walletrpc.UtxoLease) wire.OutPoint {
	var hash chainhash.Hash
	copy(hash[:], lease.Outpoint.TxidBytes)

	return wire.OutPoint{
		Hash:  hash,
		Index: lease.Outpoint.OutputIndex,
	}
}

// TestCommitVirtualPsbtsDriftReleasesCanceledCtx covers the #2209 fail-closed
// path together with the #2206 lease release. A drifted add=false response is
// returned while the request context is already canceled. Every lease must
// still be released, once, on a live context.
//
// Releasing on the canceled parent context makes ctx.Err() non-nil, so this
// test fails unless releaseLeasedOutputs detaches via context.WithoutCancel.
func TestCommitVirtualPsbtsDriftReleasesCanceledCtx(t *testing.T) {
	t.Parallel()

	template := testPacket(t, 2)
	funded := clonePacket(t, template)
	funded.UnsignedTx.AddTxOut(&wire.TxOut{
		Value:    50000,
		PkScript: []byte{0x51, 0xff},
	})

	anchorBytes, err := fn.Serialize(template)
	require.NoError(t, err)

	vPkt := &tappsbt.VPacket{
		ChainParams: &address.RegressionNetTap,
		Version:     tappsbt.V0,
	}
	virtualBytes, err := fn.Serialize(vPkt)
	require.NoError(t, err)

	leases := driftedLeases(3)
	wallet := &driftFundWallet{
		funded:   funded,
		change:   2,
		leases:   leases,
		releases: &mockReleaser{},
	}
	server := &RPCServer{
		cfg: &tapconfig.Config{
			Lnd: &lndclient.LndServices{
				WalletKit: wallet,
			},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.ErrorIs(t, ctx.Err(), context.Canceled)

	start := time.Now()
	_, err = server.CommitVirtualPsbts(
		ctx, &wrpc.CommitVirtualPsbtsRequest{
			AnchorPsbt:   anchorBytes,
			VirtualPsbts: [][]byte{virtualBytes},
			Fees: &wrpc.CommitVirtualPsbtsRequest_SatPerVbyte{
				SatPerVbyte: 1,
			},
			AnchorChangeOutput: &wrpc.CommitVirtualPsbtsRequest_Add{
				Add: false,
			},
		},
	)
	require.ErrorIs(t, err, ErrAnchorChangeAdded)

	coinSelect := wallet.fundReq.GetCoinSelect()
	add, ok := coinSelect.ChangeOutput.(*walletrpc.PsbtCoinSelect_Add)
	require.True(t, ok)
	require.False(t, add.Add)

	require.Len(t, wallet.releases.calls, len(leases))

	seen := make(map[wire.OutPoint]int, len(leases))
	for i, call := range wallet.releases.calls {
		require.NoError(t, call.ctxErr)
		require.True(t, call.hasDeadline)
		require.LessOrEqual(
			t, call.deadline.Sub(start),
			leaseReleaseTimeout+time.Second,
		)

		var lockID wtxmgr.LockID
		copy(lockID[:], leases[i].Id)
		require.Equal(t, lockID, call.lockID)

		seen[call.op]++
	}

	for _, lease := range leases {
		require.Equal(t, 1, seen[leaseOutpoint(lease)])
	}
}

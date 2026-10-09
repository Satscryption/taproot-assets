package rpcserver

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
	"github.com/stretchr/testify/require"
)

type releaseCall struct {
	lockID      wtxmgr.LockID
	op          wire.OutPoint
	ctxErr      error
	hasDeadline bool
	deadline    time.Time
}

// mockReleaser records the state of the context each release is issued on and
// fails like lnd does when that context is already canceled.
type mockReleaser struct {
	calls   []releaseCall
	failFor map[wire.OutPoint]error
}

func (m *mockReleaser) ReleaseOutput(ctx context.Context,
	lockID wtxmgr.LockID, op wire.OutPoint) error {

	dl, ok := ctx.Deadline()
	m.calls = append(m.calls, releaseCall{
		lockID: lockID, op: op, ctxErr: ctx.Err(),
		hasDeadline: ok, deadline: dl,
	})

	if err := ctx.Err(); err != nil {
		return err
	}

	return m.failFor[op]
}

func testLeases(n int) ([]*walletrpc.UtxoLease, []wire.OutPoint) {
	leases := make([]*walletrpc.UtxoLease, n)
	ops := make([]wire.OutPoint, n)
	for i := 0; i < n; i++ {
		leases[i] = &walletrpc.UtxoLease{Id: []byte{byte(i + 1)}}
		ops[i] = wire.OutPoint{Index: uint32(i)}
	}

	return leases, ops
}

// TestReleaseLeasedOutputsCanceledContext makes sure leases are still released
// when the request context is already canceled (taproot-assets#2206).
func TestReleaseLeasedOutputsCanceledContext(t *testing.T) {
	t.Parallel()

	leases, ops := testLeases(3)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	m := &mockReleaser{}
	start := time.Now()
	releaseLeasedOutputs(ctx, m, leases, ops)

	require.Len(t, m.calls, 3)
	for i, c := range m.calls {
		require.NoError(t, c.ctxErr, "release %d ran on dead ctx", i)
		require.Equal(t, ops[i], c.op)
		require.Equal(t, wtxmgr.LockID{byte(i + 1)}, c.lockID)

		// The release context must be bounded.
		require.True(t, c.hasDeadline)
		require.LessOrEqual(
			t, c.deadline.Sub(start),
			leaseReleaseTimeout+time.Second,
		)
	}

	// Sanity check the test itself: releasing on the canceled request
	// context directly (the old behaviour) fails.
	old := &mockReleaser{}
	err := old.ReleaseOutput(ctx, wtxmgr.LockID{}, wire.OutPoint{})
	require.ErrorIs(t, err, context.Canceled)
}

// TestReleaseLeasedOutputsKeepsValues makes sure context values of the request
// context are preserved.
func TestReleaseLeasedOutputsKeepsValues(t *testing.T) {
	t.Parallel()

	type key struct{}
	parent := context.WithValue(context.Background(), key{}, "v")

	var got any
	w := &valueReleaser{key: key{}, out: &got}
	leases, ops := testLeases(1)
	releaseLeasedOutputs(parent, w, leases, ops)
	require.Equal(t, "v", got)
}

type valueReleaser struct {
	key any
	out *any
}

func (v *valueReleaser) ReleaseOutput(ctx context.Context, _ wtxmgr.LockID,
	_ wire.OutPoint) error {

	*v.out = ctx.Value(v.key)
	return nil
}

// TestReleaseLeasedOutputsContinuesOnError makes sure one failing release
// doesn't prevent the remaining leases from being released.
func TestReleaseLeasedOutputsContinuesOnError(t *testing.T) {
	t.Parallel()

	leases, ops := testLeases(3)
	m := &mockReleaser{
		failFor: map[wire.OutPoint]error{
			ops[0]: errors.New("boom"),
		},
	}
	releaseLeasedOutputs(context.Background(), m, leases, ops)
	require.Len(t, m.calls, 3)
}

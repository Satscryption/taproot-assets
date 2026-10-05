package rpcserver

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lightninglabs/taproot-assets/taprpc"
	wrpc "github.com/lightninglabs/taproot-assets/taprpc/assetwalletrpc"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// stubClock is a mutex-guarded clock. Tests advance it without sleeping,
// and commit retention reads it through RPCServer.commitNow.
type stubClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *stubClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.now
}

func (c *stubClock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.now = c.now.Add(d)
}

func newRetentionServer(store *memCommitStore, clock *stubClock,
	window time.Duration) *RPCServer {

	srv := newIdempotencyServer(store)
	srv.cfg.CommitVirtualPsbtRetention = window
	srv.commitNow = clock.Now

	return srv
}

// TestCommitVirtualPsbtsRetentionDropsCompleted tests that a completed
// response is replayed inside the retention window and funded again
// once that window has passed. A pending row is kept even when its
// claim time is older than the cutoff. An unstamped completed row from
// before finish times were stored is dropped when its claim is older
// than the window, and a recent one is replayed and then stamped.
func TestCommitVirtualPsbtsRetentionDropsCompleted(t *testing.T) {
	t.Parallel()

	// The stub starts ahead of the wall clock. A pending row stamps
	// CreatedAt with time.Now, which is then before the cutoff, so a
	// purge that used that timestamp would delete it.
	start := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Second)
	clock := &stubClock{now: start}
	store := newMemCommitStore()
	srv := newRetentionServer(store, clock, time.Hour)

	var calls atomic.Int32
	once := successOnce(&calls)
	req := commitIDRequest([]byte("retain-done"))
	ctx := context.Background()

	first, err := srv.commitVirtualPsbts(ctx, req, once)
	require.NoError(t, err)
	require.EqualValues(t, 1, calls.Load())

	clock.Add(30 * time.Minute)
	second, err := srv.commitVirtualPsbts(ctx, req, once)
	require.NoError(t, err)
	require.EqualValues(t, 1, calls.Load())
	require.True(t, proto.Equal(first, second))

	clock.Add(31 * time.Minute)
	statusResp, err := srv.GetCommitVirtualPsbtsStatus(
		ctx, &wrpc.GetCommitVirtualPsbtsStatusRequest{
			RequestId: req.RequestId,
		},
	)
	require.NoError(t, err)
	require.Equal(t, commitStatusUnknown, statusResp.Status)

	third, err := srv.commitVirtualPsbts(ctx, req, once)
	require.NoError(t, err)
	require.EqualValues(t, 2, calls.Load())
	require.True(t, proto.Equal(first, third))

	// A pending attempt stays pending across a jump past the window.
	blocked := make(chan struct{})
	release := make(chan struct{})
	pendingReq := commitIDRequest([]byte("retain-pending"))
	var pendingCalls atomic.Int32
	var pendingWG sync.WaitGroup
	pendingWG.Add(1)
	errCh := make(chan error, 1)
	go func() {
		defer pendingWG.Done()

		_, callErr := srv.commitVirtualPsbts(
			ctx, pendingReq, blockingSuccess(
				&pendingCalls, blocked, release,
			),
		)
		errCh <- callErr
	}()

	<-blocked
	clock.Add(48 * time.Hour)
	pendingStatus, err := srv.GetCommitVirtualPsbtsStatus(
		ctx, &wrpc.GetCommitVirtualPsbtsStatusRequest{
			RequestId: pendingReq.RequestId,
		},
	)
	require.NoError(t, err)
	require.Equal(t, commitStatusPendingProto, pendingStatus.Status)

	close(release)
	pendingWG.Wait()
	require.NoError(t, <-errCh)
	require.EqualValues(t, 1, pendingCalls.Load())

	// Legacy completed rows have no finish stamp. An old one is
	// removed and funded again. A recent one is replayed, then
	// stamped so the next purge does not read the blob.
	oldReq := commitIDRequest([]byte("retain-legacy-old"))
	insertCompletedUnstamped(
		t, store, oldReq, clock.Now().Add(-48*time.Hour),
	)
	var oldCalls atomic.Int32
	_, err = srv.commitVirtualPsbts(ctx, oldReq, successOnce(&oldCalls))
	require.NoError(t, err)
	require.EqualValues(t, 1, oldCalls.Load())

	freshReq := commitIDRequest([]byte("retain-legacy-fresh"))
	insertCompletedUnstamped(
		t, store, freshReq, clock.Now().Add(-time.Minute),
	)
	var freshCalls atomic.Int32
	replayed, err := srv.commitVirtualPsbts(
		ctx, freshReq, successOnce(&freshCalls),
	)
	require.NoError(t, err)
	require.EqualValues(t, 0, freshCalls.Load())
	require.True(t, proto.Equal(
		cannedCommitResponse([]*taprpc.OutPoint{testLeaseOutpoint()}),
		replayed,
	))

	unstamped, err := store.ListUnstampedCommitRecords(ctx)
	require.NoError(t, err)
	for _, row := range unstamped {
		require.NotEqual(t, freshReq.RequestId, row.RequestID)
	}
}

func blockingSuccess(calls *atomic.Int32, blocked,
	release chan struct{}) commitOnceFunc {

	utxos := []*taprpc.OutPoint{testLeaseOutpoint()}

	return func(_ context.Context, _ *wrpc.CommitVirtualPsbtsRequest,
		hooks *commitVirtualPsbtsHooks) (
		*wrpc.CommitVirtualPsbtsResponse, error) {

		calls.Add(1)
		close(blocked)
		<-release

		resp := cannedCommitResponse(utxos)
		if hooks == nil {
			return resp, nil
		}

		err := hooks.onFunded(
			append([]byte(nil), testLeaseLock...), utxos,
			time.Time{},
		)
		if err != nil {
			return nil, err
		}

		err = hooks.onResult(resp)
		if err != nil {
			return nil, err
		}

		return resp, nil
	}
}

func insertCompletedUnstamped(t *testing.T, store *memCommitStore,
	req *wrpc.CommitVirtualPsbtsRequest, created time.Time) {

	t.Helper()

	ensureCommitLockID(req)
	hash, err := hashCommitRequest(req)
	require.NoError(t, err)

	resp, err := proto.Marshal(cannedCommitResponse(
		[]*taprpc.OutPoint{testLeaseOutpoint()},
	))
	require.NoError(t, err)

	raw, err := encodeCommitRecord(&commitRecord{
		Status:      commitStatusCompleted,
		RequestHash: hash,
		LockID:      append([]byte(nil), req.CustomLockId...),
		Outpoints:   []*taprpc.OutPoint{testLeaseOutpoint()},
		Response:    resp,
		CreatedAt:   created,
	})
	require.NoError(t, err)
	require.NoError(t, store.InsertCommitRecord(
		context.Background(), req.RequestId, raw,
	))
}

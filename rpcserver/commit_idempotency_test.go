package rpcserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/tapconfig"
	"github.com/lightninglabs/taproot-assets/tapdb"
	"github.com/lightninglabs/taproot-assets/taprpc"
	wrpc "github.com/lightninglabs/taproot-assets/taprpc/assetwalletrpc"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
)

var (
	testCustomLock = bytes.Repeat([]byte{0x11}, 32)
	testLeaseLock  = bytes.Repeat([]byte{0x22}, 32)
	testLeaseTxid  = bytes.Repeat([]byte{0x33}, 32)
)

func testLeaseOutpoint() *taprpc.OutPoint {
	return &taprpc.OutPoint{
		Txid:        append([]byte(nil), testLeaseTxid...),
		OutputIndex: 7,
	}
}

func cannedCommitResponse(
	utxos []*taprpc.OutPoint) *wrpc.CommitVirtualPsbtsResponse {

	return &wrpc.CommitVirtualPsbtsResponse{
		AnchorPsbt:        []byte("funded-anchor"),
		VirtualPsbts:      [][]byte{{0x0a}},
		ChangeOutputIndex: 3,
		LndLockedUtxos:    utxos,
	}
}

func commitIDRequest(id []byte) *wrpc.CommitVirtualPsbtsRequest {
	return &wrpc.CommitVirtualPsbtsRequest{
		RequestId:    append([]byte(nil), id...),
		VirtualPsbts: [][]byte{{0x01}},
		AnchorPsbt:   []byte("template"),
		CustomLockId: append([]byte(nil), testCustomLock...),
	}
}

func newIdempotencyServer(store tapconfig.CommitIdempotencyStore) *RPCServer {
	return &RPCServer{
		cfg: &tapconfig.Config{
			ChainParams:       address.MainNetTap,
			CommitIdempotency: store,
		},
	}
}

// memCommitStore is an in-memory CommitIdempotencyStore.
type memCommitStore struct {
	mu      sync.Mutex
	rows    map[string][]byte
	inserts atomic.Int32
	deletes atomic.Int32
}

func newMemCommitStore() *memCommitStore {
	return &memCommitStore{rows: make(map[string][]byte)}
}

func (m *memCommitStore) InsertCommitRecord(_ context.Context, id,
	record []byte) error {

	m.mu.Lock()
	defer m.mu.Unlock()

	m.inserts.Add(1)

	key := string(id)
	if _, ok := m.rows[key]; ok {
		return &tapdb.ErrSqlUniqueConstraintViolation{}
	}

	m.rows[key] = append([]byte(nil), record...)

	return nil
}

func (m *memCommitStore) FetchCommitRecord(_ context.Context,
	id []byte) ([]byte, error) {

	m.mu.Lock()
	defer m.mu.Unlock()

	record, ok := m.rows[string(id)]
	if !ok {
		return nil, tapdb.ErrNoCommitRecord
	}

	return append([]byte(nil), record...), nil
}

func (m *memCommitStore) UpdateCommitRecord(_ context.Context, id,
	record []byte) error {

	m.mu.Lock()
	defer m.mu.Unlock()

	key := string(id)
	if _, ok := m.rows[key]; !ok {
		return tapdb.ErrNoCommitRecord
	}

	m.rows[key] = append([]byte(nil), record...)

	return nil
}

func (m *memCommitStore) DeleteCommitRecord(_ context.Context,
	id []byte) error {

	m.mu.Lock()
	defer m.mu.Unlock()

	m.deletes.Add(1)
	delete(m.rows, string(id))

	return nil
}

func successOnce(calls *atomic.Int32) commitOnceFunc {
	utxos := []*taprpc.OutPoint{testLeaseOutpoint()}

	return func(_ context.Context, _ *wrpc.CommitVirtualPsbtsRequest,
		hooks *commitVirtualPsbtsHooks) (
		*wrpc.CommitVirtualPsbtsResponse, error) {

		calls.Add(1)

		resp := cannedCommitResponse(utxos)
		if hooks == nil {
			return resp, nil
		}

		err := hooks.onFunded(
			append([]byte(nil), testLeaseLock...), utxos,
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

// TestCommitVirtualPsbtsReplaySkipsSecondCommit tests that a repeated
// request ID returns the stored response and does not run the commit
// again.
func TestCommitVirtualPsbtsReplaySkipsSecondCommit(t *testing.T) {
	t.Parallel()

	store := newMemCommitStore()
	srv := newIdempotencyServer(store)
	req := commitIDRequest([]byte("req-1"))

	var calls atomic.Int32
	once := successOnce(&calls)

	ctx := context.Background()
	first, err := srv.commitVirtualPsbts(ctx, req, once)
	require.NoError(t, err)

	second, err := srv.commitVirtualPsbts(ctx, req, once)
	require.NoError(t, err)
	require.EqualValues(t, 1, calls.Load())
	require.True(t, proto.Equal(first, second))

	other := commitIDRequest([]byte("req-2"))
	_, err = srv.commitVirtualPsbts(ctx, other, once)
	require.NoError(t, err)
	require.EqualValues(t, 2, calls.Load())

	statusResp, err := srv.GetCommitVirtualPsbtsStatus(
		ctx, &wrpc.GetCommitVirtualPsbtsStatusRequest{
			RequestId: req.RequestId,
		},
	)
	require.NoError(t, err)
	require.Equal(t, commitStatusCompletedProto, statusResp.Status)
	require.Equal(t, testLeaseLock, statusResp.LockId)
	require.True(t, proto.Equal(
		testLeaseOutpoint(), statusResp.LndLockedUtxos[0],
	))
}

// TestCommitVirtualPsbtsEmptyRequestIDIsNotStored tests that omitting the
// request ID keeps the historical stateless behaviour.
func TestCommitVirtualPsbtsEmptyRequestIDIsNotStored(t *testing.T) {
	t.Parallel()

	store := newMemCommitStore()
	srv := newIdempotencyServer(store)
	req := commitIDRequest(nil)
	req.CustomLockId = nil

	var calls atomic.Int32
	var sawHooks atomic.Bool
	once := func(_ context.Context, got *wrpc.CommitVirtualPsbtsRequest,
		hooks *commitVirtualPsbtsHooks) (
		*wrpc.CommitVirtualPsbtsResponse, error) {

		calls.Add(1)
		if hooks != nil {
			sawHooks.Store(true)
		}
		require.Empty(t, got.CustomLockId)

		return cannedCommitResponse(nil), nil
	}

	ctx := context.Background()
	_, err := srv.commitVirtualPsbts(ctx, req, once)
	require.NoError(t, err)
	_, err = srv.commitVirtualPsbts(ctx, req, once)
	require.NoError(t, err)

	require.EqualValues(t, 2, calls.Load())
	require.False(t, sawHooks.Load())
	require.EqualValues(t, 0, store.inserts.Load())
}

// TestCommitVirtualPsbtsRequestMismatch tests that reusing a request ID
// with a different body does not fund and does not replace the stored
// result.
func TestCommitVirtualPsbtsRequestMismatch(t *testing.T) {
	t.Parallel()

	store := newMemCommitStore()
	srv := newIdempotencyServer(store)
	req := commitIDRequest([]byte("req"))

	var calls atomic.Int32
	once := successOnce(&calls)
	ctx := context.Background()

	first, err := srv.commitVirtualPsbts(ctx, req, once)
	require.NoError(t, err)

	mismatch := commitIDRequest(req.RequestId)
	mismatch.AnchorPsbt = []byte("other-template")
	_, err = srv.commitVirtualPsbts(ctx, mismatch, once)
	assertCode(t, err, codes.InvalidArgument)
	require.EqualValues(t, 1, calls.Load())

	again, err := srv.commitVirtualPsbts(ctx, req, once)
	require.NoError(t, err)
	require.True(t, proto.Equal(first, again))
	require.EqualValues(t, 1, calls.Load())
}

// TestCommitVirtualPsbtsPendingDoesNotFund tests that a request ID left
// pending (the process died after funding, or the call is in progress)
// is not funded again. The status RPC returns the recorded leases.
func TestCommitVirtualPsbtsPendingDoesNotFund(t *testing.T) {
	t.Parallel()

	store := newMemCommitStore()
	srv := newIdempotencyServer(store)
	req := commitIDRequest([]byte("pending"))
	ensureCommitLockID(req)

	hash, err := hashCommitRequest(req)
	require.NoError(t, err)

	utxo := testLeaseOutpoint()
	raw, err := encodeCommitRecord(&commitRecord{
		Status:      commitStatusPending,
		RequestHash: hash,
		LockID:      append([]byte(nil), testLeaseLock...),
		Outpoints:   []*taprpc.OutPoint{utxo},
	})
	require.NoError(t, err)
	require.NoError(t, store.InsertCommitRecord(
		context.Background(), req.RequestId, raw,
	))

	var calls atomic.Int32
	_, err = srv.commitVirtualPsbts(
		context.Background(), req, successOnce(&calls),
	)
	assertCode(t, err, codes.Aborted)
	require.EqualValues(t, 0, calls.Load())

	statusResp, err := srv.GetCommitVirtualPsbtsStatus(
		context.Background(),
		&wrpc.GetCommitVirtualPsbtsStatusRequest{
			RequestId: req.RequestId,
		},
	)
	require.NoError(t, err)
	require.Equal(t, commitStatusPendingProto, statusResp.Status)
	require.Equal(t, testLeaseLock, statusResp.LockId)
	require.True(t, proto.Equal(utxo, statusResp.LndLockedUtxos[0]))
}

// TestCommitVirtualPsbtsFailureAfterFundingRetries tests that a failed
// attempt releases the request ID, so a later call funds again instead
// of sticking on the pending row.
func TestCommitVirtualPsbtsFailureAfterFundingRetries(t *testing.T) {
	t.Parallel()

	store := newMemCommitStore()
	srv := newIdempotencyServer(store)
	req := commitIDRequest([]byte("retry"))

	var calls atomic.Int32
	utxos := []*taprpc.OutPoint{testLeaseOutpoint()}
	once := func(_ context.Context, _ *wrpc.CommitVirtualPsbtsRequest,
		hooks *commitVirtualPsbtsHooks) (
		*wrpc.CommitVirtualPsbtsResponse, error) {

		n := calls.Add(1)
		require.NotNil(t, hooks)
		err := hooks.onFunded(
			append([]byte(nil), testLeaseLock...), utxos,
		)
		require.NoError(t, err)

		if n == 1 {
			return nil, context.DeadlineExceeded
		}

		resp := cannedCommitResponse(utxos)
		require.NoError(t, hooks.onResult(resp))

		return resp, nil
	}

	ctx := context.Background()
	_, err := srv.commitVirtualPsbts(ctx, req, once)
	require.ErrorIs(t, err, context.DeadlineExceeded)

	statusResp, err := srv.GetCommitVirtualPsbtsStatus(
		ctx, &wrpc.GetCommitVirtualPsbtsStatusRequest{
			RequestId: req.RequestId,
		},
	)
	require.NoError(t, err)
	require.Equal(t, commitStatusUnknown, statusResp.Status)
	require.EqualValues(t, 1, store.deletes.Load())

	resp, err := srv.commitVirtualPsbts(ctx, req, once)
	require.NoError(t, err)
	require.EqualValues(t, 2, calls.Load())
	require.True(t, proto.Equal(cannedCommitResponse(utxos), resp))
}

// TestCommitVirtualPsbtsStatusDuringCommit tests the pending record
// before funding, the leased outpoints after funding, and the derived
// lock ID used when the caller does not set one.
func TestCommitVirtualPsbtsStatusDuringCommit(t *testing.T) {
	t.Parallel()

	store := newMemCommitStore()
	srv := newIdempotencyServer(store)
	req := commitIDRequest([]byte("derive-me"))
	req.CustomLockId = nil

	var calls atomic.Int32
	utxos := []*taprpc.OutPoint{testLeaseOutpoint()}
	once := func(_ context.Context, got *wrpc.CommitVirtualPsbtsRequest,
		hooks *commitVirtualPsbtsHooks) (
		*wrpc.CommitVirtualPsbtsResponse, error) {

		calls.Add(1)

		sum := sha256.Sum256(req.RequestId)
		require.Equal(t, sum[:], got.CustomLockId)

		statusResp, err := srv.GetCommitVirtualPsbtsStatus(
			context.Background(),
			&wrpc.GetCommitVirtualPsbtsStatusRequest{
				RequestId: req.RequestId,
			},
		)
		require.NoError(t, err)
		require.Equal(t, commitStatusPendingProto, statusResp.Status)
		require.Equal(t, sum[:], statusResp.LockId)
		require.Empty(t, statusResp.LndLockedUtxos)

		err = hooks.onFunded(
			append([]byte(nil), testLeaseLock...), utxos,
		)
		require.NoError(t, err)

		statusResp, err = srv.GetCommitVirtualPsbtsStatus(
			context.Background(),
			&wrpc.GetCommitVirtualPsbtsStatusRequest{
				RequestId: req.RequestId,
			},
		)
		require.NoError(t, err)
		require.Equal(t, commitStatusPendingProto, statusResp.Status)
		require.Equal(t, testLeaseLock, statusResp.LockId)
		require.True(t, proto.Equal(
			utxos[0], statusResp.LndLockedUtxos[0],
		))

		resp := cannedCommitResponse(utxos)
		require.NoError(t, hooks.onResult(resp))

		return resp, nil
	}

	ctx := context.Background()
	unknown, err := srv.GetCommitVirtualPsbtsStatus(
		ctx, &wrpc.GetCommitVirtualPsbtsStatusRequest{
			RequestId: req.RequestId,
		},
	)
	require.NoError(t, err)
	require.Equal(t, commitStatusUnknown, unknown.Status)

	resp, err := srv.commitVirtualPsbts(ctx, req, once)
	require.NoError(t, err)
	require.EqualValues(t, 1, calls.Load())

	again, err := srv.commitVirtualPsbts(ctx, req, once)
	require.NoError(t, err)
	require.EqualValues(t, 1, calls.Load())
	require.True(t, proto.Equal(resp, again))
}

// TestCommitVirtualPsbtsConcurrentRequestIDFundsOnce tests that two
// overlapping calls with the same request ID fund once.
func TestCommitVirtualPsbtsConcurrentRequestIDFundsOnce(t *testing.T) {
	t.Parallel()

	store := newMemCommitStore()
	srv := newIdempotencyServer(store)
	req := commitIDRequest([]byte("race"))

	var calls atomic.Int32
	started := make(chan struct{})
	release := make(chan struct{})
	var onceStart sync.Once

	once := func(ctx context.Context, got *wrpc.CommitVirtualPsbtsRequest,
		hooks *commitVirtualPsbtsHooks) (
		*wrpc.CommitVirtualPsbtsResponse, error) {

		calls.Add(1)
		onceStart.Do(func() { close(started) })
		<-release

		return successOnce(&atomic.Int32{})(ctx, got, hooks)
	}

	errCh := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	for i := 0; i < 2; i++ {
		go func() {
			defer wg.Done()

			raw := proto.Clone(req)
			cloned, ok := raw.(*wrpc.CommitVirtualPsbtsRequest)
			require.True(t, ok)

			_, err := srv.commitVirtualPsbts(
				context.Background(), cloned, once,
			)
			errCh <- err
		}()
	}

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the first commit")
	}

	select {
	case err := <-errCh:
		require.Error(t, err)
		assertCode(t, err, codes.Aborted)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the duplicate commit")
	}

	close(release)
	wg.Wait()

	require.NoError(t, <-errCh)
	require.EqualValues(t, 1, calls.Load())
}

// TestCommitVirtualPsbtsRequestIDValidation tests rejection of an empty
// status key, an overlong request ID, and a missing store.
func TestCommitVirtualPsbtsRequestIDValidation(t *testing.T) {
	t.Parallel()

	store := newMemCommitStore()
	srv := newIdempotencyServer(store)
	ctx := context.Background()

	_, err := srv.GetCommitVirtualPsbtsStatus(
		ctx, &wrpc.GetCommitVirtualPsbtsStatusRequest{},
	)
	assertCode(t, err, codes.InvalidArgument)

	_, err = srv.GetCommitVirtualPsbtsStatus(ctx, nil)
	assertCode(t, err, codes.InvalidArgument)

	var calls atomic.Int32
	longID := bytes.Repeat([]byte{0x01}, maxCommitRequestIDLen+1)
	req := commitIDRequest(longID)
	_, err = srv.commitVirtualPsbts(ctx, req, successOnce(&calls))
	assertCode(t, err, codes.InvalidArgument)
	require.EqualValues(t, 0, calls.Load())

	unconfigured := &RPCServer{cfg: &tapconfig.Config{}}
	_, err = unconfigured.commitVirtualPsbts(
		ctx, commitIDRequest([]byte("x")), successOnce(&calls),
	)
	assertCode(t, err, codes.Internal)
	require.EqualValues(t, 0, calls.Load())
}

// TestCommitVirtualPsbtsFailureReleasesRequestID tests that a real
// CommitVirtualPsbts failure claims the request ID and then drops it,
// so the key is not stuck pending.
func TestCommitVirtualPsbtsFailureReleasesRequestID(t *testing.T) {
	t.Parallel()

	store := newMemCommitStore()
	srv := newIdempotencyServer(store)
	req := &wrpc.CommitVirtualPsbtsRequest{
		RequestId: []byte("bad-proof"),
		VirtualPsbts: [][]byte{
			{0x01},
		},
		TransitionProofVersion: wrpc.TransitionProofVersion(2),
	}

	_, err := srv.CommitVirtualPsbts(context.Background(), req)
	assertCode(t, err, codes.InvalidArgument)
	require.EqualValues(t, 1, store.inserts.Load())
	require.EqualValues(t, 1, store.deletes.Load())

	statusResp, err := srv.GetCommitVirtualPsbtsStatus(
		context.Background(),
		&wrpc.GetCommitVirtualPsbtsStatusRequest{
			RequestId: req.RequestId,
		},
	)
	require.NoError(t, err)
	require.Equal(t, commitStatusUnknown, statusResp.Status)
}

// TestCommitVirtualPsbtsIdempotentSurvivesNewStore tests that a completed
// request ID is replayed from the database by a new store instance.
func TestCommitVirtualPsbtsIdempotentSurvivesNewStore(t *testing.T) {
	t.Parallel()

	db := tapdb.NewTestDB(t)
	srv := newIdempotencyServer(tapdb.NewCommitVirtualPsbtStoreFromDB(db))
	req := commitIDRequest([]byte("durable"))

	var calls atomic.Int32
	once := successOnce(&calls)
	ctx := context.Background()

	first, err := srv.commitVirtualPsbts(ctx, req, once)
	require.NoError(t, err)

	restarted := newIdempotencyServer(
		tapdb.NewCommitVirtualPsbtStoreFromDB(db),
	)
	second, err := restarted.commitVirtualPsbts(ctx, req, once)
	require.NoError(t, err)
	require.EqualValues(t, 1, calls.Load())
	require.True(t, proto.Equal(first, second))

	statusResp, err := restarted.GetCommitVirtualPsbtsStatus(
		ctx, &wrpc.GetCommitVirtualPsbtsStatusRequest{
			RequestId: req.RequestId,
		},
	)
	require.NoError(t, err)
	require.Equal(t, commitStatusCompletedProto, statusResp.Status)
	require.Equal(t, testLeaseLock, statusResp.LockId)
}

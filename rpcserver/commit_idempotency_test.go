package rpcserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"math"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/tapconfig"
	"github.com/lightninglabs/taproot-assets/tapdb"
	"github.com/lightninglabs/taproot-assets/taprpc"
	wrpc "github.com/lightninglabs/taproot-assets/taprpc/assetwalletrpc"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
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

// leaseWallet is the subset of lnd's wallet the recovery path queries.
// ListLeases is the existing lease listing RPC.
type leaseWallet struct {
	lndclient.WalletKitClient

	leases  []lndclient.LeaseDescriptor
	listErr error
}

func (w *leaseWallet) ListLeases(context.Context) (
	[]lndclient.LeaseDescriptor, error) {

	if w.listErr != nil {
		return nil, w.listErr
	}

	out := make([]lndclient.LeaseDescriptor, len(w.leases))
	copy(out, w.leases)

	return out, nil
}

func newLeaseServer(store tapconfig.CommitIdempotencyStore,
	wallet lndclient.WalletKitClient) *RPCServer {

	srv := newIdempotencyServer(store)
	srv.cfg.Lnd = &lndclient.LndServices{WalletKit: wallet}

	return srv
}

// releaseWallet records ReleaseOutput calls. ListLeases still comes
// from the embedded lease wallet.
type releaseWallet struct {
	leaseWallet

	mu       sync.Mutex
	released []wire.OutPoint
	lockIDs  []wtxmgr.LockID
}

func (w *releaseWallet) ReleaseOutput(_ context.Context, id wtxmgr.LockID,
	op wire.OutPoint) error {

	w.mu.Lock()
	defer w.mu.Unlock()

	w.released = append(w.released, op)
	w.lockIDs = append(w.lockIDs, id)

	return nil
}

func testLockID(raw []byte) wtxmgr.LockID {
	var id wtxmgr.LockID
	copy(id[:], raw)

	return id
}

func describedLease(lock []byte, op *taprpc.OutPoint,
	expiry time.Time) lndclient.LeaseDescriptor {

	var hash chainhash.Hash
	copy(hash[:], op.Txid)

	return lndclient.LeaseDescriptor{
		LockID: testLockID(lock),
		Outpoint: wire.OutPoint{
			Hash:  hash,
			Index: op.OutputIndex,
		},
		Expiration: expiry,
	}
}

func insertPendingCommit(t *testing.T, store *memCommitStore,
	req *wrpc.CommitVirtualPsbtsRequest, lock []byte,
	utxos []*taprpc.OutPoint) {

	t.Helper()

	ensureCommitLockID(req)
	hash, err := hashCommitRequest(req)
	require.NoError(t, err)

	raw, err := encodeCommitRecord(&commitRecord{
		Status:      commitStatusPending,
		RequestHash: hash,
		LockID:      append([]byte(nil), lock...),
		Outpoints:   utxos,
	})
	require.NoError(t, err)
	require.NoError(t, store.InsertCommitRecord(
		context.Background(), req.RequestId, raw,
	))
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

func (m *memCommitStore) SwapCommitRecord(_ context.Context, id, expected,
	next []byte) error {

	m.mu.Lock()
	defer m.mu.Unlock()

	current, ok := m.rows[string(id)]
	if !ok {
		return tapdb.ErrNoCommitRecord
	}
	if !bytes.Equal(current, expected) {
		return tapdb.ErrCommitRecordChanged
	}

	m.rows[string(id)] = append([]byte(nil), next...)

	return nil
}

func (m *memCommitStore) ListCommitRecords(context.Context) (
	[]tapdb.CommitRecordRow, error) {

	m.mu.Lock()
	defer m.mu.Unlock()

	rows := make([]tapdb.CommitRecordRow, 0, len(m.rows))
	for id, record := range m.rows {
		rows = append(rows, tapdb.CommitRecordRow{
			RequestID: append([]byte(nil), id...),
			Record:    append([]byte(nil), record...),
		})
	}

	return rows, nil
}

func (m *memCommitStore) DeleteCommitRecordIf(_ context.Context, id,
	expected []byte) error {

	m.mu.Lock()
	defer m.mu.Unlock()

	current, ok := m.rows[string(id)]
	if !ok {
		return tapdb.ErrNoCommitRecord
	}
	if !bytes.Equal(current, expected) {
		return tapdb.ErrCommitRecordChanged
	}

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
			time.Time{},
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
			time.Time{},
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

// TestCommitVirtualPsbtsStalePendingFundsAgain tests a crash after
// onFunded succeeds and before onResult stores the PSBT. onFunded has
// already written the leased outpoints onto the pending row, and the
// funded packet existed only in memory. Once lnd no longer leases
// those outpoints, a repeat of CommitVirtualPsbts takes the request
// over and funds again. It does not stay Aborted, and the request ID
// is not stranded for good.
func TestCommitVirtualPsbtsStalePendingFundsAgain(t *testing.T) {
	t.Parallel()

	store := newMemCommitStore()
	utxo := testLeaseOutpoint()
	wallet := &leaseWallet{}
	srv := newLeaseServer(store, wallet)
	req := commitIDRequest([]byte("stale-funded"))
	insertPendingCommit(
		t, store, req, testLeaseLock, []*taprpc.OutPoint{utxo},
	)

	ctx := context.Background()
	statusResp, err := srv.GetCommitVirtualPsbtsStatus(
		ctx, &wrpc.GetCommitVirtualPsbtsStatusRequest{
			RequestId: req.RequestId,
		},
	)
	require.NoError(t, err)
	require.Equal(t, commitStatusPendingProto, statusResp.Status)
	require.Equal(t, testLeaseLock, statusResp.LockId)
	require.True(t, proto.Equal(utxo, statusResp.LndLockedUtxos[0]))

	var calls atomic.Int32
	resp, err := srv.commitVirtualPsbts(
		ctx, req, successOnce(&calls),
	)
	require.NoError(t, err)
	require.EqualValues(t, 1, calls.Load())
	require.True(t, proto.Equal(cannedCommitResponse(
		[]*taprpc.OutPoint{utxo},
	), resp))

	mismatch := commitIDRequest(req.RequestId)
	mismatch.AnchorPsbt = []byte("other-template")
	_, err = srv.commitVirtualPsbts(ctx, mismatch, successOnce(&calls))
	assertCode(t, err, codes.InvalidArgument)
	require.EqualValues(t, 1, calls.Load())
}

// TestCommitVirtualPsbtsPendingLeaseStillHeld tests that a pending row
// whose outpoints are still leased is not funded again.
func TestCommitVirtualPsbtsPendingLeaseStillHeld(t *testing.T) {
	t.Parallel()

	store := newMemCommitStore()
	utxo := testLeaseOutpoint()
	wallet := &leaseWallet{
		leases: []lndclient.LeaseDescriptor{
			describedLease(
				testLeaseLock, utxo, time.Now().Add(time.Hour),
			),
		},
	}
	srv := newLeaseServer(store, wallet)
	req := commitIDRequest([]byte("still-leased"))
	insertPendingCommit(
		t, store, req, testLeaseLock, []*taprpc.OutPoint{utxo},
	)

	var calls atomic.Int32
	_, err := srv.commitVirtualPsbts(
		context.Background(), req, successOnce(&calls),
	)
	assertCode(t, err, codes.Aborted)
	require.EqualValues(t, 0, calls.Load())
}

// TestCommitVirtualPsbtsFailedReleaseKeepsPending tests that a failed
// attempt whose leases are still held does not delete the request ID.
func TestCommitVirtualPsbtsFailedReleaseKeepsPending(t *testing.T) {
	t.Parallel()

	store := newMemCommitStore()
	utxo := testLeaseOutpoint()
	wallet := &leaseWallet{
		leases: []lndclient.LeaseDescriptor{
			describedLease(
				testLeaseLock, utxo, time.Now().Add(time.Hour),
			),
		},
	}
	srv := newLeaseServer(store, wallet)
	req := commitIDRequest([]byte("release-failed"))

	var calls atomic.Int32
	once := func(_ context.Context, _ *wrpc.CommitVirtualPsbtsRequest,
		hooks *commitVirtualPsbtsHooks) (
		*wrpc.CommitVirtualPsbtsResponse, error) {

		calls.Add(1)
		err := hooks.onFunded(
			append([]byte(nil), testLeaseLock...),
			[]*taprpc.OutPoint{utxo}, time.Time{},
		)
		require.NoError(t, err)

		return nil, errors.New("release would fail")
	}

	ctx := context.Background()
	_, err := srv.commitVirtualPsbts(ctx, req, once)
	require.Error(t, err)
	require.EqualValues(t, 1, calls.Load())
	require.EqualValues(t, 0, store.deletes.Load())

	statusResp, err := srv.GetCommitVirtualPsbtsStatus(
		ctx, &wrpc.GetCommitVirtualPsbtsStatusRequest{
			RequestId: req.RequestId,
		},
	)
	require.NoError(t, err)
	require.Equal(t, commitStatusPendingProto, statusResp.Status)
	require.Equal(t, testLeaseLock, statusResp.LockId)
	require.True(t, proto.Equal(utxo, statusResp.LndLockedUtxos[0]))

	_, err = srv.commitVirtualPsbts(ctx, req, once)
	assertCode(t, err, codes.Aborted)
	require.EqualValues(t, 1, calls.Load())
}

// TestCommitVirtualPsbtsUnrecordedLeaseBackfill tests that a crash
// after FundPsbt returns and before the pending row stores outpoints
// still reports those leases, and does not fund while they are held.
func TestCommitVirtualPsbtsUnrecordedLeaseBackfill(t *testing.T) {
	t.Parallel()

	store := newMemCommitStore()
	utxo := testLeaseOutpoint()
	wallet := &leaseWallet{
		leases: []lndclient.LeaseDescriptor{
			describedLease(
				testCustomLock, utxo,
				time.Now().Add(time.Hour),
			),
		},
	}
	srv := newLeaseServer(store, wallet)
	req := commitIDRequest([]byte("gap-funded"))
	insertPendingCommit(t, store, req, testCustomLock, nil)

	ctx := context.Background()
	statusResp, err := srv.GetCommitVirtualPsbtsStatus(
		ctx, &wrpc.GetCommitVirtualPsbtsStatusRequest{
			RequestId: req.RequestId,
		},
	)
	require.NoError(t, err)
	require.Equal(t, commitStatusPendingProto, statusResp.Status)
	require.Equal(t, testCustomLock, statusResp.LockId)
	require.Len(t, statusResp.LndLockedUtxos, 1)
	require.True(t, proto.Equal(utxo, statusResp.LndLockedUtxos[0]))

	var calls atomic.Int32
	_, err = srv.commitVirtualPsbts(ctx, req, successOnce(&calls))
	assertCode(t, err, codes.Aborted)
	require.EqualValues(t, 0, calls.Load())
}

// TestCommitVirtualPsbtsFailedReleaseBeforeOnFunded tests that a
// funding error before outpoints are stored still keeps the request
// ID when lnd holds the lock ID.
func TestCommitVirtualPsbtsFailedReleaseBeforeOnFunded(t *testing.T) {
	t.Parallel()

	store := newMemCommitStore()
	utxo := testLeaseOutpoint()
	wallet := &leaseWallet{
		leases: []lndclient.LeaseDescriptor{
			describedLease(
				testCustomLock, utxo, time.Now().Add(time.Hour),
			),
		},
	}
	srv := newLeaseServer(store, wallet)
	req := commitIDRequest([]byte("release-before-record"))

	var calls atomic.Int32
	once := func(_ context.Context, _ *wrpc.CommitVirtualPsbtsRequest,
		_ *commitVirtualPsbtsHooks) (
		*wrpc.CommitVirtualPsbtsResponse, error) {

		calls.Add(1)

		return nil, errors.New("funding cleanup failed")
	}

	ctx := context.Background()
	_, err := srv.commitVirtualPsbts(ctx, req, once)
	require.Error(t, err)
	require.EqualValues(t, 0, store.deletes.Load())

	_, err = srv.commitVirtualPsbts(ctx, req, once)
	assertCode(t, err, codes.Aborted)
	require.EqualValues(t, 1, calls.Load())
}

// TestCommitVirtualPsbtsLeaseQueryErrorKeepsFundedPending tests that a
// failed attempt which already recorded outpoints is not dropped when
// the lease query itself fails.
func TestCommitVirtualPsbtsLeaseQueryErrorKeepsFundedPending(t *testing.T) {
	t.Parallel()

	store := newMemCommitStore()
	wallet := &leaseWallet{listErr: errors.New("wallet unavailable")}
	srv := newLeaseServer(store, wallet)
	req := commitIDRequest([]byte("lease-query-down"))
	utxo := testLeaseOutpoint()

	var calls atomic.Int32
	once := func(_ context.Context, _ *wrpc.CommitVirtualPsbtsRequest,
		hooks *commitVirtualPsbtsHooks) (
		*wrpc.CommitVirtualPsbtsResponse, error) {

		calls.Add(1)
		err := hooks.onFunded(
			append([]byte(nil), testLeaseLock...),
			[]*taprpc.OutPoint{utxo}, time.Time{},
		)
		require.NoError(t, err)

		return nil, errors.New("later failure")
	}

	_, err := srv.commitVirtualPsbts(context.Background(), req, once)
	require.Error(t, err)
	require.EqualValues(t, 0, store.deletes.Load())
	require.EqualValues(t, 1, calls.Load())
}

// TestCommitVirtualPsbtsReplacedAttemptDoesNotFinish tests that an
// attempt whose row was taken over by a retry cannot record its
// result on top of the replacement.
func TestCommitVirtualPsbtsReplacedAttemptDoesNotFinish(t *testing.T) {
	t.Parallel()

	store := newMemCommitStore()
	srv := newIdempotencyServer(store)
	req := commitIDRequest([]byte("fence"))
	utxo := testLeaseOutpoint()

	started := make(chan struct{})
	release := make(chan struct{})
	once := func(_ context.Context, _ *wrpc.CommitVirtualPsbtsRequest,
		hooks *commitVirtualPsbtsHooks) (
		*wrpc.CommitVirtualPsbtsResponse, error) {

		err := hooks.onFunded(
			append([]byte(nil), testLeaseLock...),
			[]*taprpc.OutPoint{utxo}, time.Time{},
		)
		require.NoError(t, err)
		close(started)
		<-release

		resp := cannedCommitResponse([]*taprpc.OutPoint{utxo})
		err = hooks.onResult(resp)
		if err != nil {
			return nil, err
		}

		return resp, nil
	}

	errCh := make(chan error, 1)
	go func() {
		_, err := srv.commitVirtualPsbts(
			context.Background(), req, once,
		)
		errCh <- err
	}()

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the commit attempt")
	}

	ensureCommitLockID(req)
	hash, err := hashCommitRequest(req)
	require.NoError(t, err)
	replacementLock := bytes.Repeat([]byte{0x44}, 32)
	replacement, err := encodeCommitRecord(&commitRecord{
		Status:      commitStatusPending,
		RequestHash: hash,
		LockID:      replacementLock,
	})
	require.NoError(t, err)
	require.NoError(t, store.UpdateCommitRecord(
		context.Background(), req.RequestId, replacement,
	))
	close(release)

	require.Error(t, <-errCh)

	raw, err := store.FetchCommitRecord(
		context.Background(), req.RequestId,
	)
	require.NoError(t, err)
	rec, err := decodeCommitRecord(raw)
	require.NoError(t, err)
	require.Equal(t, commitStatusPending, rec.Status)
	require.Equal(t, replacementLock, rec.LockID)
}

// TestCommitVirtualPsbtsReplacedAttemptReleasesOwnOutputs tests that a
// delayed attempt, whose row a retry has replaced, releases the
// outpoints it acquired and leaves the replacement's outpoints locked.
// Both attempts use the same lnd lock ID.
func TestCommitVirtualPsbtsReplacedAttemptReleasesOwnOutputs(t *testing.T) {
	t.Parallel()

	store := newMemCommitStore()
	wallet := &releaseWallet{}
	srv := newLeaseServer(store, wallet)
	req := commitIDRequest([]byte("replaced-release"))
	own := testLeaseOutpoint()
	shared := &taprpc.OutPoint{
		Txid:        bytes.Repeat([]byte{0x55}, 32),
		OutputIndex: 4,
	}

	once := func(_ context.Context, _ *wrpc.CommitVirtualPsbtsRequest,
		hooks *commitVirtualPsbtsHooks) (
		*wrpc.CommitVirtualPsbtsResponse, error) {

		ensureCommitLockID(req)
		hash, err := hashCommitRequest(req)
		require.NoError(t, err)

		replacement, err := encodeCommitRecord(&commitRecord{
			Status:      commitStatusPending,
			RequestHash: hash,
			LockID:      append([]byte(nil), req.CustomLockId...),
			Outpoints:   []*taprpc.OutPoint{shared},
			CreatedAt:   time.Unix(1_700_000_000, 0),
		})
		require.NoError(t, err)
		require.NoError(t, store.UpdateCommitRecord(
			context.Background(), req.RequestId, replacement,
		))

		err = hooks.onFunded(
			append([]byte(nil), req.CustomLockId...),
			[]*taprpc.OutPoint{own, shared}, time.Time{},
		)
		require.ErrorIs(t, err, errCommitAttemptReplaced)

		return nil, err
	}

	_, err := srv.commitVirtualPsbts(context.Background(), req, once)
	require.ErrorIs(t, err, errCommitAttemptReplaced)

	wallet.mu.Lock()
	released := append([]wire.OutPoint(nil), wallet.released...)
	lockIDs := append([]wtxmgr.LockID(nil), wallet.lockIDs...)
	wallet.mu.Unlock()

	require.Len(t, released, 1)
	require.Equal(t, own.OutputIndex, released[0].Index)
	require.Equal(t, own.Txid, released[0].Hash[:])
	require.Len(t, lockIDs, 1)
	require.Equal(t, testLockID(req.CustomLockId), lockIDs[0])

	raw, err := store.FetchCommitRecord(
		context.Background(), req.RequestId,
	)
	require.NoError(t, err)
	rec, err := decodeCommitRecord(raw)
	require.NoError(t, err)
	require.Len(t, rec.Outpoints, 1)
	require.True(t, proto.Equal(shared, rec.Outpoints[0]))
}

// TestCommitVirtualPsbtsSharedLockDoesNotAdoptForeignLease tests that
// a pending row does not record or keep leases it cannot attribute to
// itself when another request uses the same caller-chosen lock ID.
func TestCommitVirtualPsbtsSharedLockDoesNotAdoptForeignLease(
	t *testing.T) {

	t.Parallel()

	lock := append([]byte(nil), testCustomLock...)
	foreign := &taprpc.OutPoint{
		Txid:        bytes.Repeat([]byte{0x66}, 32),
		OutputIndex: 2,
	}
	own := &taprpc.OutPoint{
		Txid:        bytes.Repeat([]byte{0x77}, 32),
		OutputIndex: 3,
	}

	t.Run("recorded neighbor", func(t *testing.T) {
		store := newMemCommitStore()
		wallet := &leaseWallet{
			leases: []lndclient.LeaseDescriptor{
				describedLease(
					lock, foreign,
					time.Now().Add(time.Hour),
				),
				describedLease(
					lock, own, time.Now().Add(time.Hour),
				),
			},
		}
		srv := newLeaseServer(store, wallet)

		other := commitIDRequest([]byte("other-recorded"))
		insertPendingCommit(
			t, store, other, lock,
			[]*taprpc.OutPoint{foreign},
		)

		req := commitIDRequest([]byte("this-recorded"))
		insertPendingCommit(t, store, req, lock, nil)

		statusResp, err := srv.GetCommitVirtualPsbtsStatus(
			context.Background(),
			&wrpc.GetCommitVirtualPsbtsStatusRequest{
				RequestId: req.RequestId,
			},
		)
		require.NoError(t, err)
		require.Equal(t, commitStatusPendingProto, statusResp.Status)
		require.Len(t, statusResp.LndLockedUtxos, 1)
		require.True(t, proto.Equal(own, statusResp.LndLockedUtxos[0]))
	})

	t.Run("unrecorded neighbor", func(t *testing.T) {
		store := newMemCommitStore()
		wallet := &leaseWallet{
			leases: []lndclient.LeaseDescriptor{
				describedLease(
					lock, foreign,
					time.Now().Add(time.Hour),
				),
			},
		}
		srv := newLeaseServer(store, wallet)

		other := commitIDRequest([]byte("other-open"))
		insertPendingCommit(t, store, other, lock, nil)

		req := commitIDRequest([]byte("this-open"))
		ensureCommitLockID(req)
		hash, err := hashCommitRequest(req)
		require.NoError(t, err)
		raw, err := encodeCommitRecord(&commitRecord{
			Status:      commitStatusPending,
			RequestHash: hash,
			LockID:      append([]byte(nil), lock...),
			CreatedAt:   time.Now().Add(-time.Hour),
			LeaseExpiry: time.Now().Add(-time.Minute),
		})
		require.NoError(t, err)
		require.NoError(t, store.InsertCommitRecord(
			context.Background(), req.RequestId, raw,
		))

		var calls atomic.Int32
		_, err = srv.commitVirtualPsbts(
			context.Background(), req, successOnce(&calls),
		)
		require.NoError(t, err)
		require.EqualValues(t, 1, calls.Load())

		raw, err = store.FetchCommitRecord(
			context.Background(), other.RequestId,
		)
		require.NoError(t, err)
		otherRec, err := decodeCommitRecord(raw)
		require.NoError(t, err)
		require.Empty(t, otherRec.Outpoints)
	})
}

// encodeCommitRecordV1 writes the original record layout, which has no
// lease timestamps.
func encodeCommitRecordV1(t *testing.T, rec *commitRecord) []byte {
	t.Helper()

	savedCreated := rec.CreatedAt
	savedExpiry := rec.LeaseExpiry
	rec.CreatedAt = time.Time{}
	rec.LeaseExpiry = time.Time{}
	t.Cleanup(func() {
		rec.CreatedAt = savedCreated
		rec.LeaseExpiry = savedExpiry
	})

	raw, err := encodeCommitRecord(rec)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(raw), 17)
	raw[0] = commitRecordVersion1

	return raw[:len(raw)-16]
}

// TestCommitVirtualPsbtsV1StalePendingFundsAgain tests that a pending
// row written before lease timestamps were stored is funded again once
// its outpoints are no longer leased.
func TestCommitVirtualPsbtsV1StalePendingFundsAgain(t *testing.T) {
	t.Parallel()

	store := newMemCommitStore()
	srv := newLeaseServer(store, &leaseWallet{})
	req := commitIDRequest([]byte("v1-stale"))
	utxo := testLeaseOutpoint()

	ensureCommitLockID(req)
	hash, err := hashCommitRequest(req)
	require.NoError(t, err)
	raw := encodeCommitRecordV1(t, &commitRecord{
		Status:      commitStatusPending,
		RequestHash: hash,
		LockID:      append([]byte(nil), testLeaseLock...),
		Outpoints:   []*taprpc.OutPoint{utxo},
	})
	require.NoError(t, store.InsertCommitRecord(
		context.Background(), req.RequestId, raw,
	))

	var calls atomic.Int32
	_, err = srv.commitVirtualPsbts(
		context.Background(), req, successOnce(&calls),
	)
	require.NoError(t, err)
	require.EqualValues(t, 1, calls.Load())
}

// TestCommitVirtualPsbtsUnrecordedLeaseExpiresFundsAgain tests that a
// crash between FundPsbt and the pending-row update can be retried
// once the lease deadline has passed and lnd holds no matching lease.
func TestCommitVirtualPsbtsUnrecordedLeaseExpiresFundsAgain(t *testing.T) {
	t.Parallel()

	store := newMemCommitStore()
	srv := newLeaseServer(store, &leaseWallet{})
	req := commitIDRequest([]byte("gap-expired"))
	ensureCommitLockID(req)
	hash, err := hashCommitRequest(req)
	require.NoError(t, err)

	raw, err := encodeCommitRecord(&commitRecord{
		Status:      commitStatusPending,
		RequestHash: hash,
		LockID:      append([]byte(nil), req.CustomLockId...),
		CreatedAt:   time.Now().Add(-time.Hour),
		LeaseExpiry: time.Now().Add(-time.Minute),
	})
	require.NoError(t, err)
	require.NoError(t, store.InsertCommitRecord(
		context.Background(), req.RequestId, raw,
	))

	var calls atomic.Int32
	_, err = srv.commitVirtualPsbts(
		context.Background(), req, successOnce(&calls),
	)
	require.NoError(t, err)
	require.EqualValues(t, 1, calls.Load())
}

// TestCommitVirtualPsbtsUnrecordedLeaseBeforeExpiryStaysAborted tests
// that a pending row with no outpoints is not taken over before its
// lease deadline while lnd also reports no lease. That is the window
// before FundPsbt returns.
func TestCommitVirtualPsbtsUnrecordedLeaseBeforeExpiryStaysAborted(
	t *testing.T) {

	t.Parallel()

	store := newMemCommitStore()
	srv := newLeaseServer(store, &leaseWallet{})
	req := commitIDRequest([]byte("gap-inflight"))
	ensureCommitLockID(req)
	hash, err := hashCommitRequest(req)
	require.NoError(t, err)

	raw, err := encodeCommitRecord(&commitRecord{
		Status:      commitStatusPending,
		RequestHash: hash,
		LockID:      append([]byte(nil), req.CustomLockId...),
		CreatedAt:   time.Now(),
		LeaseExpiry: time.Now().Add(time.Hour),
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
}

// TestCommitVirtualPsbtsStalePendingMismatch tests that an expired
// pending row is not replaced when the retry body differs.
func TestCommitVirtualPsbtsStalePendingMismatch(t *testing.T) {
	t.Parallel()

	store := newMemCommitStore()
	srv := newLeaseServer(store, &leaseWallet{})
	req := commitIDRequest([]byte("stale-mismatch"))
	insertPendingCommit(
		t, store, req, testLeaseLock,
		[]*taprpc.OutPoint{testLeaseOutpoint()},
	)

	mismatch := commitIDRequest(req.RequestId)
	mismatch.AnchorPsbt = []byte("other-template")

	var calls atomic.Int32
	_, err := srv.commitVirtualPsbts(
		context.Background(), mismatch, successOnce(&calls),
	)
	assertCode(t, err, codes.InvalidArgument)
	require.EqualValues(t, 0, calls.Load())
	require.EqualValues(t, 0, store.deletes.Load())
}

// TestCommitVirtualPsbtsReleasedFailureRetries tests that a failed
// attempt whose leases are gone releases the request ID.
func TestCommitVirtualPsbtsReleasedFailureRetries(t *testing.T) {
	t.Parallel()

	store := newMemCommitStore()
	srv := newLeaseServer(store, &leaseWallet{})
	req := commitIDRequest([]byte("released"))
	utxo := testLeaseOutpoint()

	var calls atomic.Int32
	once := func(_ context.Context, _ *wrpc.CommitVirtualPsbtsRequest,
		hooks *commitVirtualPsbtsHooks) (
		*wrpc.CommitVirtualPsbtsResponse, error) {

		n := calls.Add(1)
		err := hooks.onFunded(
			append([]byte(nil), testLeaseLock...),
			[]*taprpc.OutPoint{utxo}, time.Time{},
		)
		require.NoError(t, err)
		if n == 1 {
			return nil, errors.New("commit failed after release")
		}

		resp := cannedCommitResponse([]*taprpc.OutPoint{utxo})
		require.NoError(t, hooks.onResult(resp))

		return resp, nil
	}

	ctx := context.Background()
	_, err := srv.commitVirtualPsbts(ctx, req, once)
	require.Error(t, err)
	require.EqualValues(t, 1, store.deletes.Load())

	_, err = srv.commitVirtualPsbts(ctx, req, once)
	require.NoError(t, err)
	require.EqualValues(t, 2, calls.Load())
}

// TestCommitVirtualPsbtsRetainPendingSkipsAbandon tests that a failed
// release keeps the request ID even when the lease list is empty, and
// a later retry funds once the row is stale.
func TestCommitVirtualPsbtsRetainPendingSkipsAbandon(t *testing.T) {
	t.Parallel()

	store := newMemCommitStore()
	srv := newLeaseServer(store, &leaseWallet{})
	req := commitIDRequest([]byte("retain"))
	utxo := testLeaseOutpoint()

	var calls atomic.Int32
	once := func(_ context.Context, _ *wrpc.CommitVirtualPsbtsRequest,
		hooks *commitVirtualPsbtsHooks) (
		*wrpc.CommitVirtualPsbtsResponse, error) {

		n := calls.Add(1)
		err := hooks.onFunded(
			append([]byte(nil), testLeaseLock...),
			[]*taprpc.OutPoint{utxo}, time.Time{},
		)
		require.NoError(t, err)
		if n == 1 {
			hooks.retainPending = true

			return nil, errors.New("release output failed")
		}

		resp := cannedCommitResponse([]*taprpc.OutPoint{utxo})
		require.NoError(t, hooks.onResult(resp))

		return resp, nil
	}

	ctx := context.Background()
	_, err := srv.commitVirtualPsbts(ctx, req, once)
	require.Error(t, err)
	require.EqualValues(t, 0, store.deletes.Load())

	_, err = srv.commitVirtualPsbts(ctx, req, once)
	require.NoError(t, err)
	require.EqualValues(t, 2, calls.Load())
}

// TestCommitVirtualPsbtsHugeLockStaysPending tests that a lock duration
// past the UnixNano range does not decode as an already-expired lease.
// Recovery must not replace that still-pending request.
func TestCommitVirtualPsbtsHugeLockStaysPending(t *testing.T) {
	t.Parallel()

	store := newMemCommitStore()
	srv := newLeaseServer(store, &leaseWallet{})
	req := commitIDRequest([]byte("huge-lock"))
	req.LockExpirationSeconds = math.MaxUint64

	release := make(chan struct{})
	var closed sync.Once
	closeRelease := func() {
		closed.Do(func() { close(release) })
	}
	t.Cleanup(closeRelease)

	started := make(chan struct{})
	var calls atomic.Int32
	once := func(_ context.Context, _ *wrpc.CommitVirtualPsbtsRequest,
		hooks *commitVirtualPsbtsHooks) (
		*wrpc.CommitVirtualPsbtsResponse, error) {

		calls.Add(1)
		close(started)
		<-release

		resp := cannedCommitResponse(nil)
		if err := hooks.onResult(resp); err != nil {
			return nil, err
		}

		return resp, nil
	}

	errCh := make(chan error, 1)
	go func() {
		_, err := srv.commitVirtualPsbts(
			context.Background(), req, once,
		)
		errCh <- err
	}()

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the commit attempt")
	}

	raw, err := store.FetchCommitRecord(
		context.Background(), req.RequestId,
	)
	require.NoError(t, err)
	rec, err := decodeCommitRecord(raw)
	require.NoError(t, err)

	var retryCalls atomic.Int32
	_, err = srv.commitVirtualPsbts(
		context.Background(), req, successOnce(&retryCalls),
	)
	if err == nil {
		t.Fatalf("retry funded a still-pending request; "+
			"decoded lease expiry %s", rec.LeaseExpiry.UTC())
	}
	assertCode(t, err, codes.Aborted)
	require.EqualValues(t, 0, retryCalls.Load())
	require.True(t, time.Now().Before(rec.LeaseExpiry),
		"decoded lease expiry %s", rec.LeaseExpiry.UTC())

	closeRelease()
	require.NoError(t, <-errCh)
	require.EqualValues(t, 1, calls.Load())
}

// TestUtxoLeaseExpiryBeyondUnixNanoStaysFuture tests that an lnd lease
// expiration that does not fit in UnixNano is not stored as a past
// deadline. MaxUint64 used to wrap through int64; MaxInt64 seconds is
// past the last representable nanosecond timestamp.
func TestUtxoLeaseExpiryBeyondUnixNanoStaysFuture(t *testing.T) {
	t.Parallel()

	deadlines := []uint64{
		math.MaxUint64,
		uint64(math.MaxInt64),
	}
	for _, sec := range deadlines {
		exp := earliestUtxoLeaseExpiry([]*walletrpc.UtxoLease{
			{Expiration: sec},
		})
		raw, err := encodeCommitRecord(&commitRecord{
			Status:      commitStatusPending,
			CreatedAt:   time.Now(),
			LeaseExpiry: exp,
		})
		require.NoError(t, err)

		rec, err := decodeCommitRecord(raw)
		require.NoError(t, err)
		require.True(t, time.Now().Before(rec.LeaseExpiry),
			"seconds %d decoded as %s", sec,
			rec.LeaseExpiry.UTC())
	}

	soon := time.Now().Add(time.Hour).Unix()
	exp := earliestUtxoLeaseExpiry([]*walletrpc.UtxoLease{
		{Expiration: uint64(soon)},
	})
	require.Equal(t, soon, exp.Unix())
}

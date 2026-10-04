package supplyverifier

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/lightninglabs/taproot-assets/universe/supplycommit"
	"github.com/stretchr/testify/require"
)

// singleAttemptRetry disables backoff so tests that pin other
// contracts are not multiplied by the default retry budget.
func singleAttemptRetry() *fn.RetryConfig {
	return &fn.RetryConfig{MaxRetries: 0}
}

// fastRetry retries with no delay. maxRetries is the number of retries
// after the first attempt.
func fastRetry(maxRetries int) *fn.RetryConfig {
	return &fn.RetryConfig{
		MaxRetries:        maxRetries,
		InitialBackoff:    0,
		BackoffMultiplier: 1,
		MaxBackoff:        0,
	}
}

// recordingUniverseClient counts inserts, optionally failing them.
type recordingUniverseClient struct {
	inserts int
	fail    error
}

func (c *recordingUniverseClient) InsertSupplyCommit(_ context.Context,
	_ asset.Specifier, _ supplycommit.RootCommitment,
	_ supplycommit.SupplyLeaves, _ supplycommit.ChainProof) error {

	c.inserts++

	return c.fail
}

func (c *recordingUniverseClient) FetchSupplyCommit(_ context.Context,
	_ asset.Specifier, _ fn.Option[wire.OutPoint]) (
	supplycommit.FetchSupplyCommitResult, error) {

	return supplycommit.FetchSupplyCommitResult{}, errors.New("unused")
}

func (c *recordingUniverseClient) Close() error {
	return nil
}

// recordingSyncerStore records logged pushes and serves them back as
// the pushed-servers view, the way the durable push log does.
type recordingSyncerStore struct {
	mu     sync.Mutex
	logged []string
}

func (s *recordingSyncerStore) LogSupplyCommitPush(_ context.Context,
	serverAddr universe.ServerAddr, _ asset.Specifier,
	_ supplycommit.RootCommitment, _ supplycommit.SupplyLeaves) error {

	s.mu.Lock()
	defer s.mu.Unlock()
	s.logged = append(s.logged, serverAddr.HostStr())

	return nil
}

func (s *recordingSyncerStore) FetchPushedServers(_ context.Context,
	_ asset.Specifier, _ supplycommit.RootCommitment) ([]string, error) {

	s.mu.Lock()
	defer s.mu.Unlock()

	return append([]string(nil), s.logged...), nil
}

// staticFederationView serves a fixed server list.
type staticFederationView struct {
	servers []universe.ServerAddr
}

func (f *staticFederationView) UniverseServers(
	_ context.Context) ([]universe.ServerAddr, error) {

	return f.servers, nil
}

// TestPushSupplyCommitmentSkipsPushed pins the retry contract of the
// commitment push: a server the push log records as delivered is not
// pushed to again. The dispatcher retries the whole effect whenever
// any one server fails, so without the skip every retry re-presents
// the commitment to servers that already integrated it — and a
// receiver without the re-push absorb answers that with its outpoint
// uniqueness violation, keeping the dispatch's error set non-empty
// and its bookkeeping open forever.
func TestPushSupplyCommitmentSkipsPushed(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	addrA := universe.NewServerAddrFromStr("a.example:10029")
	addrB := universe.NewServerAddrFromStr("b.example:10029")

	clients := map[string]*recordingUniverseClient{
		addrA.HostStr(): {},
		addrB.HostStr(): {fail: errors.New("refused")},
	}
	store := &recordingSyncerStore{}
	syncer := NewSupplySyncer(SupplySyncerConfig{
		ClientFactory: func(
			sa universe.ServerAddr) (UniverseClient, error) {

			return clients[sa.HostStr()], nil
		},
		Store: store,
		UniverseFederationView: &staticFederationView{
			servers: []universe.ServerAddr{addrA, addrB},
		},
		Retry: singleAttemptRetry(),
	})

	spec := asset.NewSpecifierFromGroupKey(*test.RandPubKey(t))
	commitment := supplycommit.RootCommitment{Txn: wire.NewMsgTx(2)}

	push := func() map[string]error {
		errMap, err := syncer.PushSupplyCommitment(
			ctx, spec, commitment, supplycommit.SupplyLeaves{},
			supplycommit.ChainProof{}, nil,
		)
		require.NoError(t, err)

		return errMap
	}

	// First attempt: both servers are targeted; A succeeds and is
	// logged, B fails and is reported.
	errMap := push()
	require.Len(t, errMap, 1)
	require.Contains(t, errMap, addrB.HostStr())
	require.Equal(t, 1, clients[addrA.HostStr()].inserts)
	require.Equal(t, 1, clients[addrB.HostStr()].inserts)
	require.Equal(t, []string{addrA.HostStr()}, store.logged)

	// The retry consults the push log and targets only the server
	// still missing the commitment; once it accepts, the error set
	// is empty and the dispatch can finally report success.
	clients[addrB.HostStr()].fail = nil

	errMap = push()
	require.Empty(t, errMap)
	require.Equal(t, 1, clients[addrA.HostStr()].inserts)
	require.Equal(t, 2, clients[addrB.HostStr()].inserts)

	// A further redelivery, with every server already logged, pushes
	// to nobody.
	errMap = push()
	require.Empty(t, errMap)
	require.Equal(t, 1, clients[addrA.HostStr()].inserts)
	require.Equal(t, 2, clients[addrB.HostStr()].inserts)
}

// TestManagerInsertSupplyCommitAbsorbsRePush pins the receiver half of
// the same contract: a pushed commitment already stored under its
// outpoint is absorbed before verification. Re-verifying would apply
// the leaves against the already-updated supply tree and fail, turning
// every legitimate re-push into a spurious error.
func TestManagerInsertSupplyCommitAbsorbsRePush(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	view := &MockSupplyCommitView{}
	spec := asset.NewSpecifierFromGroupKey(*test.RandPubKey(t))
	commitment := supplycommit.RootCommitment{
		Txn:      wire.NewMsgTx(2),
		TxOutIdx: 0,
	}

	view.On(
		"FetchCommitmentByOutpoint", ctx, spec,
		commitment.CommitPoint(),
	).Return(&supplycommit.RootCommitment{}, nil)

	m := &Manager{cfg: ManagerCfg{SupplyCommitView: view}}
	err := m.InsertSupplyCommit(
		ctx, spec, commitment, supplycommit.SupplyLeaves{},
	)
	require.NoError(t, err)

	// The absorb happens before verification and before any insert.
	view.AssertNotCalled(t, "InsertSupplyCommit")

	// An unexpected lookup failure propagates rather than being
	// mistaken for absence.
	view2 := &MockSupplyCommitView{}
	view2.On(
		"FetchCommitmentByOutpoint", ctx, spec,
		commitment.CommitPoint(),
	).Return(nil, errors.New("db down"))

	m2 := &Manager{cfg: ManagerCfg{SupplyCommitView: view2}}
	err = m2.InsertSupplyCommit(
		ctx, spec, commitment, supplycommit.SupplyLeaves{},
	)
	require.ErrorContains(t, err, "db down")
}

// scriptedUniverse is a UniverseClient and dialer. It records inserts
// and can reject a commitment whose spent outpoint it has not seen.
type scriptedUniverse struct {
	mu sync.Mutex

	dials        int
	dialFailLeft int

	inserts []wire.OutPoint
	known   map[wire.OutPoint]struct{}

	// failInsertsLeft returns insertErr that many times before the
	// normal accept/reject path.
	failInsertsLeft int
	insertErr       error

	fetches       int
	fetchFailLeft int
	fetchErr      error
	fetchResult   supplycommit.FetchSupplyCommitResult

	// onInsert, when set, replaces the insert body.
	onInsert func(ctx context.Context) error
}

func newScriptedUniverse() *scriptedUniverse {
	return &scriptedUniverse{
		known: make(map[wire.OutPoint]struct{}),
	}
}

func (s *scriptedUniverse) factory(
	_ universe.ServerAddr) (UniverseClient, error) {

	s.mu.Lock()
	defer s.mu.Unlock()

	s.dials++
	if s.dialFailLeft > 0 {
		s.dialFailLeft--

		return nil, errors.New("dial failed")
	}

	return s, nil
}

func (s *scriptedUniverse) InsertSupplyCommit(ctx context.Context,
	_ asset.Specifier, commitment supplycommit.RootCommitment,
	_ supplycommit.SupplyLeaves, _ supplycommit.ChainProof) error {

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.onInsert != nil {
		return s.onInsert(ctx)
	}

	point := commitment.CommitPoint()
	s.inserts = append(s.inserts, point)

	if s.failInsertsLeft > 0 {
		s.failInsertsLeft--

		return s.insertErr
	}

	if commitment.SpentCommitment.IsSome() {
		spent, err := commitment.SpentCommitment.UnwrapOrErr(
			errors.New("missing spent outpoint"),
		)
		if err != nil {
			return err
		}
		if _, ok := s.known[spent]; !ok {
			return ErrPrevCommitmentNotFound
		}
	}

	s.known[point] = struct{}{}

	return nil
}

func (s *scriptedUniverse) FetchSupplyCommit(_ context.Context,
	_ asset.Specifier, _ fn.Option[wire.OutPoint]) (
	supplycommit.FetchSupplyCommitResult, error) {

	s.mu.Lock()
	defer s.mu.Unlock()

	s.fetches++
	if s.fetchFailLeft > 0 {
		s.fetchFailLeft--

		return supplycommit.FetchSupplyCommitResult{}, s.fetchErr
	}

	return s.fetchResult, nil
}

func (s *scriptedUniverse) Close() error {
	return nil
}

func (s *scriptedUniverse) snapshot() (dials int, inserts []wire.OutPoint,
	fetches int) {

	s.mu.Lock()
	defer s.mu.Unlock()

	return s.dials, append([]wire.OutPoint(nil), s.inserts...), s.fetches
}

// memHistory serves push payloads keyed by the commitment outpoint.
type memHistory struct {
	mu      sync.Mutex
	byOp    map[wire.OutPoint]ancestorPush
	fetches int
}

func historyOf(commits []supplycommit.RootCommitment) *memHistory {
	byOp := make(map[wire.OutPoint]ancestorPush, len(commits))
	for _, commit := range commits {
		byOp[commit.CommitPoint()] = ancestorPush{
			commitment: commit,
		}
	}

	return &memHistory{byOp: byOp}
}

func (h *memHistory) FetchSupplyCommitPush(_ context.Context,
	_ asset.Specifier, outpoint wire.OutPoint) (supplycommit.RootCommitment,
	supplycommit.SupplyLeaves, supplycommit.ChainProof, error) {

	h.mu.Lock()
	defer h.mu.Unlock()

	h.fetches++
	push, ok := h.byOp[outpoint]
	if !ok {
		var (
			zeroCommit supplycommit.RootCommitment
			zeroLeaves supplycommit.SupplyLeaves
			zeroProof  supplycommit.ChainProof
		)

		return zeroCommit, zeroLeaves, zeroProof, ErrCommitmentNotFound
	}

	return push.commitment, push.leaves, push.chainProof, nil
}

func (h *memHistory) fetchCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()

	return h.fetches
}

// rootCommit builds a distinct commitment. id selects the locktime so
// each commitment has its own outpoint.
func rootCommit(id uint32, spent fn.Option[wire.OutPoint],
) supplycommit.RootCommitment {

	tx := wire.NewMsgTx(2)
	tx.LockTime = id

	return supplycommit.RootCommitment{
		Txn:             tx,
		TxOutIdx:        0,
		SpentCommitment: spent,
	}
}

// commitChain returns n commitments, oldest first. Each spends the
// outpoint of the previous one. The first spends nothing.
func commitChain(n int) []supplycommit.RootCommitment {
	commits := make([]supplycommit.RootCommitment, n)
	var spent fn.Option[wire.OutPoint]
	for i := range commits {
		commits[i] = rootCommit(uint32(i+1), spent)
		spent = fn.Some(commits[i].CommitPoint())
	}

	return commits
}

func testSyncer(client *scriptedUniverse, hist SupplyCommitHistory,
	retry *fn.RetryConfig) SupplySyncer {

	addr := universe.NewServerAddrFromStr("uni.example:10029")

	return NewSupplySyncer(SupplySyncerConfig{
		ClientFactory: client.factory,
		Store:         &recordingSyncerStore{},
		UniverseFederationView: &staticFederationView{
			servers: []universe.ServerAddr{addr},
		},
		History: hist,
		Retry:   retry,
	})
}

func testSpec(t *testing.T) asset.Specifier {
	t.Helper()

	return asset.NewSpecifierFromGroupKey(*test.RandPubKey(t))
}

func TestSupplySyncerRetryConfigDefault(t *testing.T) {
	t.Parallel()

	syncer := NewSupplySyncer(SupplySyncerConfig{})
	require.Equal(t, fn.DefaultRetryConfig(), syncer.retryConfig())

	custom := fn.RetryConfig{MaxRetries: 3, InitialBackoff: time.Second}
	syncer = NewSupplySyncer(SupplySyncerConfig{Retry: &custom})
	require.Equal(t, custom, syncer.retryConfig())
}

// TestPushSupplyCommitmentRetriesTransientInsert pins backoff retry of
// a failed insert and of a failed dial. The sequence is bounded by the
// configured attempt count.
func TestPushSupplyCommitmentRetriesTransientInsert(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	spec := testSpec(t)
	commitment := rootCommit(1, fn.None[wire.OutPoint]())

	client := newScriptedUniverse()
	client.failInsertsLeft = 2
	client.insertErr = errors.New("unavailable")
	syncer := testSyncer(client, nil, fastRetry(4))

	errMap, err := syncer.PushSupplyCommitment(
		ctx, spec, commitment, supplycommit.SupplyLeaves{},
		supplycommit.ChainProof{}, nil,
	)
	require.NoError(t, err)
	require.Empty(t, errMap)

	_, inserts, _ := client.snapshot()
	require.Len(t, inserts, 3)

	// A dial failure is retried the same way, and the insert runs
	// only after a client is obtained.
	client = newScriptedUniverse()
	client.dialFailLeft = 2
	syncer = testSyncer(client, nil, fastRetry(4))

	errMap, err = syncer.PushSupplyCommitment(
		ctx, spec, commitment, supplycommit.SupplyLeaves{},
		supplycommit.ChainProof{}, nil,
	)
	require.NoError(t, err)
	require.Empty(t, errMap)

	dials, inserts, _ := client.snapshot()
	require.Equal(t, 3, dials)
	require.Len(t, inserts, 1)
}

// TestPullSupplyCommitmentRetriesTransientFetch pins fetch retry, and
// that a definitive miss is returned on the first attempt.
func TestPullSupplyCommitmentRetriesTransientFetch(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	spec := testSpec(t)
	client := newScriptedUniverse()
	client.fetchFailLeft = 2
	client.fetchErr = errors.New("unavailable")
	fetched := rootCommit(1, fn.None[wire.OutPoint]())
	fetched.SupplyRoot = mssmt.NewComputedBranch(
		mssmt.EmptyTreeRootHash, 0,
	)
	client.fetchResult = supplycommit.FetchSupplyCommitResult{
		RootCommitment: fetched,
	}
	syncer := testSyncer(client, nil, fastRetry(4))

	res, err := syncer.PullSupplyCommitment(
		ctx, spec, fn.None[wire.OutPoint](), nil,
	)
	require.NoError(t, err)
	require.Empty(t, res.ErrorMap)
	require.True(t, res.FetchResult.IsSome())

	_, _, fetches := client.snapshot()
	require.Equal(t, 3, fetches)

	client = newScriptedUniverse()
	client.fetchFailLeft = 5
	client.fetchErr = ErrCommitmentNotFound
	syncer = testSyncer(client, nil, fastRetry(4))

	res, err = syncer.PullSupplyCommitment(
		ctx, spec, fn.None[wire.OutPoint](), nil,
	)
	require.NoError(t, err)
	require.Len(t, res.ErrorMap, 1)
	for _, pullErr := range res.ErrorMap {
		require.ErrorIs(t, pullErr, ErrCommitmentNotFound)
	}

	_, _, fetches = client.snapshot()
	require.Equal(t, 1, fetches)
}

// TestSupplySyncRetryHonorsContext stops a retry when the caller
// cancels, both during the RPC and during the backoff wait.
func TestSupplySyncRetryHonorsContext(t *testing.T) {
	t.Parallel()

	spec := testSpec(t)
	commitment := rootCommit(1, fn.None[wire.OutPoint]())

	t.Run("during rpc", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		started := make(chan struct{})
		var once sync.Once
		client := newScriptedUniverse()
		client.onInsert = func(ctx context.Context) error {
			once.Do(func() { close(started) })
			<-ctx.Done()

			return ctx.Err()
		}
		syncer := testSyncer(client, nil, fastRetry(4))

		errCh := make(chan error, 1)
		go func() {
			_, err := syncer.PushSupplyCommitment(
				ctx, spec, commitment,
				supplycommit.SupplyLeaves{},
				supplycommit.ChainProof{}, nil,
			)
			errCh <- err
		}()

		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatal("insert did not start")
		}
		cancel()

		select {
		case err := <-errCh:
			require.ErrorIs(t, err, context.Canceled)
		case <-time.After(2 * time.Second):
			t.Fatal("retry ignored cancellation")
		}

		_, inserts, _ := client.snapshot()
		require.Empty(t, inserts)
	})

	t.Run("during backoff", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		started := make(chan struct{})
		var once sync.Once
		var calls atomicInt
		client := newScriptedUniverse()

		// A long backoff would hang the test if cancellation
		// were ignored. The hook counts calls directly because
		// it replaces the scripted insert body.
		client.onInsert = func(context.Context) error {
			calls.add()
			once.Do(func() { close(started) })

			return errors.New("unavailable")
		}
		retry := &fn.RetryConfig{
			MaxRetries:        5,
			InitialBackoff:    time.Hour,
			BackoffMultiplier: 2,
			MaxBackoff:        time.Hour,
		}
		syncer := testSyncer(client, nil, retry)

		errCh := make(chan error, 1)
		go func() {
			_, err := syncer.PushSupplyCommitment(
				ctx, spec, commitment,
				supplycommit.SupplyLeaves{},
				supplycommit.ChainProof{}, nil,
			)
			errCh <- err
		}()

		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatal("insert did not start")
		}
		cancel()

		select {
		case err := <-errCh:
			require.ErrorIs(t, err, context.Canceled)
		case <-time.After(2 * time.Second):
			t.Fatal("backoff ignored cancellation")
		}

		require.Equal(t, 1, calls.get())
	})
}

// atomicInt is a tiny counter that is safe to bump from the insert hook.
type atomicInt struct {
	mu sync.Mutex
	n  int
}

func (a *atomicInt) add() {
	a.mu.Lock()
	a.n++
	a.mu.Unlock()
}

func (a *atomicInt) get() int {
	a.mu.Lock()
	defer a.mu.Unlock()

	return a.n
}

// TestPushDoesNotRetryOrStringMatchMissing pins two boundaries: a
// missing predecessor is not burned against the retry budget, and an
// error whose text merely looks like that sentinel does not trigger a
// history load.
func TestPushDoesNotRetryOrStringMatchMissing(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	spec := testSpec(t)
	parent := rootCommit(1, fn.None[wire.OutPoint]())
	tip := rootCommit(2, fn.Some(parent.CommitPoint()))
	hist := historyOf([]supplycommit.RootCommitment{parent})

	client := newScriptedUniverse()
	syncer := testSyncer(client, nil, fastRetry(5))

	errMap, err := syncer.PushSupplyCommitment(
		ctx, spec, tip, supplycommit.SupplyLeaves{},
		supplycommit.ChainProof{}, nil,
	)
	require.NoError(t, err)
	require.Len(t, errMap, 1)
	for _, pushErr := range errMap {
		require.ErrorIs(t, pushErr, ErrPrevCommitmentNotFound)
	}

	_, inserts, _ := client.snapshot()
	require.Len(t, inserts, 1)

	client = newScriptedUniverse()
	client.insertErr = errors.New("previous supply commitment not found")
	client.failInsertsLeft = 10
	syncer = testSyncer(client, hist, fastRetry(2))

	errMap, err = syncer.PushSupplyCommitment(
		ctx, spec, tip, supplycommit.SupplyLeaves{},
		supplycommit.ChainProof{}, nil,
	)
	require.NoError(t, err)
	require.Len(t, errMap, 1)
	for _, pushErr := range errMap {
		require.NotErrorIs(t, pushErr, ErrPrevCommitmentNotFound)
	}

	_, inserts, _ = client.snapshot()
	require.Len(t, inserts, 3)
	require.Zero(t, hist.fetchCount())
}

// TestPushSupplyCommitmentInsertsMissingPredecessors inserts the gap
// oldest-first and then retries the commitment that was rejected.
func TestPushSupplyCommitmentInsertsMissingPredecessors(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	spec := testSpec(t)
	chain := commitChain(3)
	client := newScriptedUniverse()
	syncer := testSyncer(client, historyOf(chain), fastRetry(2))

	errMap, err := syncer.PushSupplyCommitment(
		ctx, spec, chain[2], supplycommit.SupplyLeaves{},
		supplycommit.ChainProof{}, nil,
	)
	require.NoError(t, err)
	require.Empty(t, errMap)

	_, inserts, _ := client.snapshot()
	require.Equal(t, []wire.OutPoint{
		chain[2].CommitPoint(),
		chain[0].CommitPoint(),
		chain[1].CommitPoint(),
		chain[2].CommitPoint(),
	}, inserts)

	// A transient failure is retried before the missing-predecessor
	// repair runs. The first tip insert fails closed; the second is
	// the rejection that starts the ordered backfill.
	client = newScriptedUniverse()
	client.failInsertsLeft = 1
	client.insertErr = errors.New("unavailable")
	syncer = testSyncer(client, historyOf(chain), fastRetry(2))

	errMap, err = syncer.PushSupplyCommitment(
		ctx, spec, chain[2], supplycommit.SupplyLeaves{},
		supplycommit.ChainProof{}, nil,
	)
	require.NoError(t, err)
	require.Empty(t, errMap)

	_, inserts, _ = client.snapshot()
	require.Equal(t, []wire.OutPoint{
		chain[2].CommitPoint(),
		chain[2].CommitPoint(),
		chain[0].CommitPoint(),
		chain[1].CommitPoint(),
		chain[2].CommitPoint(),
	}, inserts)
}

// TestPushSupplyCommitmentRejectsMismatchedHistory refuses a local
// payload whose outpoint is not the spent outpoint the server named.
func TestPushSupplyCommitmentRejectsMismatchedHistory(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	spec := testSpec(t)
	parent := rootCommit(1, fn.None[wire.OutPoint]())
	tip := rootCommit(2, fn.Some(parent.CommitPoint()))
	other := rootCommit(9, fn.None[wire.OutPoint]())

	hist := &memHistory{
		byOp: map[wire.OutPoint]ancestorPush{
			parent.CommitPoint(): {commitment: other},
		},
	}
	client := newScriptedUniverse()
	syncer := testSyncer(client, hist, fastRetry(3))

	errMap, err := syncer.PushSupplyCommitment(
		ctx, spec, tip, supplycommit.SupplyLeaves{},
		supplycommit.ChainProof{}, nil,
	)
	require.NoError(t, err)
	require.Len(t, errMap, 1)
	for _, pushErr := range errMap {
		require.ErrorContains(t, pushErr, "outpoint")
	}

	_, inserts, _ := client.snapshot()
	require.Equal(t, []wire.OutPoint{tip.CommitPoint()}, inserts)
}

// TestPushSupplyCommitmentRejectsPredecessorCycle fails closed when
// spent outpoints loop, instead of inserting forever.
func TestPushSupplyCommitmentRejectsPredecessorCycle(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	spec := testSpec(t)

	first := rootCommit(1, fn.None[wire.OutPoint]())
	second := rootCommit(2, fn.Some(first.CommitPoint()))
	first.SpentCommitment = fn.Some(second.CommitPoint())

	client := newScriptedUniverse()
	syncer := testSyncer(
		client, historyOf([]supplycommit.RootCommitment{first, second}),
		fastRetry(5),
	)

	errMap, err := syncer.PushSupplyCommitment(
		ctx, spec, second, supplycommit.SupplyLeaves{},
		supplycommit.ChainProof{}, nil,
	)
	require.NoError(t, err)
	require.Len(t, errMap, 1)
	for _, pushErr := range errMap {
		require.ErrorContains(t, pushErr, "cycle")
	}

	_, inserts, _ := client.snapshot()
	require.Len(t, inserts, 1)
}

// TestPushSupplyCommitmentBoundsAncestorChain refuses a gap longer
// than the repair limit without walking it without end.
func TestPushSupplyCommitmentBoundsAncestorChain(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	spec := testSpec(t)
	chain := commitChain(maxAncestorChain + 2)
	client := newScriptedUniverse()
	syncer := testSyncer(client, historyOf(chain), fastRetry(3))

	errMap, err := syncer.PushSupplyCommitment(
		ctx, spec, chain[len(chain)-1], supplycommit.SupplyLeaves{},
		supplycommit.ChainProof{}, nil,
	)
	require.NoError(t, err)
	require.Len(t, errMap, 1)
	for _, pushErr := range errMap {
		require.ErrorIs(t, pushErr, errSupplyChainRemainder)
	}

	_, inserts, _ := client.snapshot()
	require.Len(t, inserts, 1)
}

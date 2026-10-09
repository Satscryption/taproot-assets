package supplycommit

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/proof"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// newTestLatestCommitment creates a confirmed root commitment at the given
// height that can be used as the predecessor of an idle successor.
func newTestLatestCommitment(t *testing.T, confirmed bool,
	height uint32) RootCommitment {

	t.Helper()

	internalKey, _ := test.RandKeyDesc(t)
	supplyRoot := mssmt.NewBranch(
		mssmt.NewLeafNode([]byte("idle-left"), 0),
		mssmt.NewLeafNode([]byte("idle-right"), 0),
	)

	txOut, outputKey, err := RootCommitTxOut(
		internalKey.PubKey, nil, supplyRoot.NodeHash(),
	)
	require.NoError(t, err)

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: randOutPoint(t)})
	tx.AddTxOut(txOut)

	commit := RootCommitment{
		Txn:         tx,
		TxOutIdx:    0,
		InternalKey: internalKey,
		OutputKey:   outputKey,
		SupplyRoot:  supplyRoot,
	}
	if confirmed {
		commit.CommitmentBlock = fn.Some(CommitmentBlock{
			Height:      height,
			Hash:        chainhash.Hash{1},
			BlockHeader: &wire.BlockHeader{},
			MerkleProof: &proof.TxMerkleProof{},
		})
	}

	return commit
}

func (h *supplyCommitTestHarness) expectLatestCommit(
	commit lfn.Option[RootCommitment], times int) {

	h.t.Helper()

	h.mockCommits.On("SupplyCommit", mock.Anything, mock.Anything).Return(
		lfn.Ok(commit),
	).Times(times)
}

func newIdleHarness(t *testing.T, initial State, interval uint32,
	autoPublish bool) *supplyCommitTestHarness {

	t.Helper()

	randGroupKey := test.RandPubKey(t)
	h := newSupplyCommitTestHarness(t, &harnessCfg{
		initialState: initial,
		assetSpec:    asset.NewSpecifierFromGroupKey(*randGroupKey),
	})
	h.env.IdleCommitInterval = interval
	h.env.AutoPublishPending = autoPublish

	return h
}

// TestIdleTickDefaultState tests the idle tick handling of the DefaultState,
// which is what makes idle successor commitments happen.
func TestIdleTickDefaultState(t *testing.T) {
	t.Parallel()

	const (
		interval  = uint32(144)
		confirmed = uint32(1000)
	)

	// With idle commits disabled (the default) the tick is a no-op and no
	// dependency is touched at all.
	t.Run("disabled", func(t *testing.T) {
		h := newIdleHarness(t, &DefaultState{}, 0, false)
		h.start()
		defer h.stopAndAssert()

		h.sendEvent(&IdleTickEvent{BlockHeight: confirmed + 10_000})
		h.assertStateTransitions(&DefaultState{})
	})

	// Without any commitment there is nothing to succeed.
	t.Run("no_commitment", func(t *testing.T) {
		h := newIdleHarness(t, &DefaultState{}, interval, false)
		h.start()
		defer h.stopAndAssert()

		h.expectLatestCommit(lfn.None[RootCommitment](), 1)

		h.sendEvent(&IdleTickEvent{BlockHeight: confirmed + 10_000})
		h.assertStateTransitions(&DefaultState{})
	})

	// An unconfirmed latest commitment can't be old enough.
	t.Run("unconfirmed_commitment", func(t *testing.T) {
		h := newIdleHarness(t, &DefaultState{}, interval, false)
		h.start()
		defer h.stopAndAssert()

		h.expectLatestCommit(lfn.Some(
			newTestLatestCommitment(t, false, 0),
		), 1)

		h.sendEvent(&IdleTickEvent{BlockHeight: confirmed + 10_000})
		h.assertStateTransitions(&DefaultState{})
	})

	// One block before the deadline nothing happens.
	t.Run("not_yet_due", func(t *testing.T) {
		h := newIdleHarness(t, &DefaultState{}, interval, false)
		h.start()
		defer h.stopAndAssert()

		h.expectLatestCommit(lfn.Some(
			newTestLatestCommitment(t, true, confirmed),
		), 1)

		h.sendEvent(&IdleTickEvent{BlockHeight: confirmed + interval - 1})
		h.assertStateTransitions(&DefaultState{})
	})

	// Exactly at confirmation height + interval the idle successor starts
	// and runs through the full commitment cycle with no pending updates.
	t.Run("due_starts_successor", func(t *testing.T) {
		h := newIdleHarness(t, &DefaultState{}, interval, false)
		h.start()
		defer h.stopAndAssert()

		latest := newTestLatestCommitment(t, true, confirmed)

		// One SupplyCommit call for the idle check, one for the tx
		// creation, which must spend the latest commitment.
		h.expectLatestCommit(lfn.Some(latest), 2)
		h.mockStateLog.On(
			"BeginIdleTransition", mock.Anything, mock.Anything,
		).Return(nil, nil).Once()

		h.expectTreeFetches()
		h.mockCommits.On(
			"UnspentPrecommits", mock.Anything, mock.Anything,
			mock.Anything,
		).Return(lfn.Ok[PreCommits](nil)).Once()
		h.expectFeeEstimation()
		h.expectPsbtFunding()
		h.expectPsbtSigning()
		h.expectInsertSignedCommitTx()
		h.expectAssetLookup()
		h.expectSupplySyncer()
		h.expectBroadcastAndConfRegistration()

		h.sendEvent(&IdleTickEvent{BlockHeight: confirmed + interval})
		h.assertStateTransitions(
			&CommitTreeCreateState{},
			&CommitTxCreateState{},
			&CommitTxSignState{},
			&CommitBroadcastState{},
			&CommitBroadcastState{},
		)

		// The successor commits no updates and is ancestry linked to
		// the latest commitment.
		state := assertAndGetCurrentState[*CommitBroadcastState](h)
		transition := state.SupplyTransition
		require.Empty(t, transition.PendingUpdates)
		require.Equal(
			t, fn.Some(latest.CommitPoint()),
			transition.NewCommitment.SpentCommitment,
		)
	})

	// Dangling updates that were bound to the idle transition are
	// committed together with the idle successor.
	t.Run("due_with_dangling_updates", func(t *testing.T) {
		h := newIdleHarness(t, &DefaultState{}, interval, false)
		h.start()
		defer h.stopAndAssert()

		dangling := newTestMintEvent(
			t, test.RandPubKey(t), randOutPoint(t),
		)
		latest := newTestLatestCommitment(t, true, confirmed)
		h.expectLatestCommit(lfn.Some(latest), 2)
		h.mockStateLog.On(
			"BeginIdleTransition", mock.Anything, mock.Anything,
		).Return([]SupplyUpdateEvent{dangling}, nil).Once()

		h.expectTreeFetches()
		h.mockCommits.On(
			"UnspentPrecommits", mock.Anything, mock.Anything,
			mock.Anything,
		).Return(lfn.Ok[PreCommits](nil)).Once()
		h.expectFeeEstimation()
		h.expectPsbtFunding()
		h.expectPsbtSigning()
		h.expectInsertSignedCommitTx()
		h.expectAssetLookup()
		h.expectSupplySyncer()
		h.expectBroadcastAndConfRegistration()

		h.sendEvent(&IdleTickEvent{BlockHeight: confirmed + interval*2})
		h.assertStateTransitions(
			&CommitTreeCreateState{},
			&CommitTxCreateState{},
			&CommitTxSignState{},
			&CommitBroadcastState{},
			&CommitBroadcastState{},
		)

		state := assertAndGetCurrentState[*CommitBroadcastState](h)
		require.Equal(
			t, []SupplyUpdateEvent{dangling},
			state.SupplyTransition.PendingUpdates,
		)
	})

	// A failure to persist the idle transition is an error that is
	// reported (the machine is torn down, like for other storage errors).
	t.Run("begin_transition_error", func(t *testing.T) {
		h := newIdleHarness(t, &DefaultState{}, interval, false)
		h.start()
		defer h.stopAndAssert()

		beginErr := errors.New("db down")
		h.expectLatestCommit(lfn.Some(
			newTestLatestCommitment(t, true, confirmed),
		), 1)
		h.mockStateLog.On(
			"BeginIdleTransition", mock.Anything, mock.Anything,
		).Return(nil, beginErr).Once()
		h.expectFailure(beginErr)

		h.sendEvent(&IdleTickEvent{BlockHeight: confirmed + interval})
		h.assertNoStateTransitions()
		require.ErrorIs(t, h.mockErrReporter.GetReportedError(), beginErr)
	})
}

// TestIdleTickOtherStates makes sure an idle tick never disturbs a commitment
// cycle that is in flight.
func TestIdleTickOtherStates(t *testing.T) {
	t.Parallel()

	dummyTx := wire.NewMsgTx(2)
	dummyTx.AddTxOut(&wire.TxOut{PkScript: []byte("test"), Value: 1})
	transition := SupplyStateTransition{
		NewCommitment: RootCommitment{Txn: dummyTx},
	}

	states := []State{
		&CommitTreeCreateState{},
		&CommitTxCreateState{SupplyTransition: transition},
		&CommitTxSignState{SupplyTransition: transition},
		&CommitBroadcastState{SupplyTransition: transition},
		&CommitFinalizeState{SupplyTransition: transition},
	}
	for _, state := range states {
		t.Run(state.String(), func(t *testing.T) {
			h := newIdleHarness(t, state, 144, true)
			h.start()
			defer h.stopAndAssert()

			h.sendEvent(&IdleTickEvent{BlockHeight: 10_000})
			h.assertStateTransitions(state)
		})
	}
}

// TestIdleTickUpdatesPendingState tests the opt-in handling of idle ticks while
// updates are staged.
func TestIdleTickUpdatesPendingState(t *testing.T) {
	t.Parallel()

	mint := newTestMintEvent(t, test.RandPubKey(t), randOutPoint(t))
	pending := func() State {
		return &UpdatesPendingState{
			pendingUpdates: []SupplyUpdateEvent{mint},
		}
	}

	// By default pending updates are left alone (manual publishing).
	t.Run("idle_only_keeps_pending_updates", func(t *testing.T) {
		h := newIdleHarness(t, pending(), 144, false)
		h.start()
		defer h.stopAndAssert()

		h.sendEvent(&IdleTickEvent{BlockHeight: 10_000})
		h.assertStateTransitions(&UpdatesPendingState{})
		state := assertAndGetCurrentState[*UpdatesPendingState](h)
		require.Len(t, state.pendingUpdates, 1)
	})

	// Fully disabled: a no-op.
	t.Run("disabled", func(t *testing.T) {
		h := newIdleHarness(t, pending(), 0, false)
		h.start()
		defer h.stopAndAssert()

		h.sendEvent(&IdleTickEvent{BlockHeight: 10_000})
		h.assertStateTransitions(&UpdatesPendingState{})
	})

	// With auto publishing the next block commits the staged updates.
	t.Run("auto_publish", func(t *testing.T) {
		h := newIdleHarness(t, pending(), 0, true)
		h.start()
		defer h.stopAndAssert()

		h.expectFreezePendingTransition()
		h.expectFullCommitmentCycleMocks(true)

		h.sendEvent(&IdleTickEvent{BlockHeight: 10_000})
		h.assertStateTransitions(
			&CommitTreeCreateState{},
			&CommitTxCreateState{},
			&CommitTxSignState{},
			&CommitBroadcastState{},
			&CommitBroadcastState{},
		)
	})

	// An idle transition without updates that was persisted before a
	// restart resumes on the next idle tick.
	t.Run("resume_interrupted_idle_transition", func(t *testing.T) {
		h := newIdleHarness(t, &UpdatesPendingState{}, 144, false)
		h.start()
		defer h.stopAndAssert()

		h.mockStateLog.On("FetchState", mock.Anything, mock.Anything).Return(
			&UpdatesPendingState{},
			lfn.Some(SupplyStateTransition{}), nil,
		).Once()
		h.expectFreezePendingTransition()
		h.expectFullCommitmentCycleMocks(true)

		h.sendEvent(&IdleTickEvent{BlockHeight: 10_000})
		h.assertStateTransitions(
			&CommitTreeCreateState{},
			&CommitTxCreateState{},
			&CommitTxSignState{},
			&CommitBroadcastState{},
			&CommitBroadcastState{},
		)
	})

	// With no transition on disk, a manual tick after a restart returns to
	// the default state instead of committing an empty batch.
	t.Run("manual_tick_nothing_to_commit", func(t *testing.T) {
		h := newIdleHarness(t, &UpdatesPendingState{}, 0, false)
		h.start()
		defer h.stopAndAssert()

		h.mockStateLog.On("FetchState", mock.Anything, mock.Anything).Return(
			&DefaultState{}, lfn.None[SupplyStateTransition](), nil,
		).Once()
		h.expectCommitState()

		h.sendEvent(&CommitTickEvent{})
		h.assertStateTransitions(&DefaultState{})
	})
}

// TestManagerIdleTickLoop makes sure the manager turns block epochs into idle
// ticks for locally controlled supply commit groups, and only if enabled.
func TestManagerIdleTickLoop(t *testing.T) {
	t.Parallel()

	groupKey := test.RandPubKey(t)

	// regErr, when set, is returned by the first epoch registration.
	// A later registration succeeds. Subtests run sequentially.
	var regErr error

	setup := func(t *testing.T, cfg ManagerCfg) (*Manager, chan int32,
		chan struct{}) {

		t.Helper()

		chain := &mockChainBridge{}
		lookup := &MockAssetLookup{}
		stateLog := &mockStateMachineStore{}
		commits := &MockCommitmentTracker{}

		blocks := make(chan int32)
		errs := make(chan error)
		if regErr != nil {
			chain.On(
				"RegisterBlockEpochNtfn", mock.Anything,
			).Return(nil, nil, regErr).Once()
		}
		chain.On(
			"RegisterBlockEpochNtfn", mock.Anything,
		).Return(blocks, errs, nil).Maybe()

		lookup.On("FetchSupplyCommitAssets", mock.Anything, true).Return(
			[]btcec.PublicKey{*groupKey}, nil,
		).Maybe()
		lookup.On(
			"QueryAssetGroupByGroupKey", mock.Anything,
			mock.Anything,
		).Return(&asset.AssetGroup{
			Genesis: &asset.Genesis{Tag: "idle"},
		}, nil).Maybe()
		lookup.On(
			"FetchAssetMetaForAsset", mock.Anything, mock.Anything,
		).Return(&proof.MetaReveal{
			UniverseCommitments: true,
			DelegationKey:       fn.Some(*test.RandPubKey(t)),
		}, nil).Maybe()
		lookup.On(
			"FetchInternalKeyLocator", mock.Anything, mock.Anything,
		).Return(keychain.KeyLocator{}, nil).Maybe()

		stateLog.On("FetchState", mock.Anything, mock.Anything).Return(
			&DefaultState{}, lfn.None[SupplyStateTransition](), nil,
		).Maybe()

		// The state machine reaches out for the latest commitment when
		// it processes the tick, signal that we got there.
		ticked := make(chan struct{}, 4)
		commits.On("SupplyCommit", mock.Anything, mock.Anything).Run(
			func(mock.Arguments) { ticked <- struct{}{} },
		).Return(lfn.Ok(lfn.None[RootCommitment]())).Maybe()

		cfg.Chain = chain
		cfg.AssetLookup = lookup
		cfg.StateLog = stateLog
		cfg.Commitments = commits
		cfg.DaemonAdapters = nil

		return NewManager(cfg), blocks, ticked
	}

	t.Run("enabled", func(t *testing.T) {
		m, blocks, ticked := setup(t, ManagerCfg{IdleCommitInterval: 6})
		require.NoError(t, m.Start())
		defer func() { require.NoError(t, m.Stop()) }()

		blocks <- 1000

		select {
		case <-ticked:
		case <-time.After(testTimeout):
			t.Fatal("no idle tick reached the state machine")
		}
	})

	t.Run("disabled", func(t *testing.T) {
		m, _, _ := setup(t, ManagerCfg{})
		require.NoError(t, m.Start())
		// A second start must not subscribe after the first
		// decided the ticker is disabled.
		require.NoError(t, m.Start())
		defer func() { require.NoError(t, m.Stop()) }()

		// No epoch registration happens, and nothing ticks.
		chain := m.cfg.Chain.(*mockChainBridge)
		chain.AssertNotCalled(
			t, "RegisterBlockEpochNtfn", mock.Anything,
		)
	})

	t.Run("epoch_registration_error", func(t *testing.T) {
		cfg := ManagerCfg{IdleCommitInterval: 6}
		chain := &mockChainBridge{}
		chain.On(
			"RegisterBlockEpochNtfn", mock.Anything,
		).Return(nil, nil, errors.New("no chain")).Twice()
		cfg.Chain = chain

		m := NewManager(cfg)
		require.ErrorContains(t, m.Start(), "no chain")
		// The failed attempt must not latch. A later Start keeps
		// reporting the error and tries to subscribe again.
		require.ErrorContains(t, m.Start(), "no chain")
		chain.AssertNumberOfCalls(
			t, "RegisterBlockEpochNtfn", 2,
		)
		require.NoError(t, m.Stop())
	})

	t.Run("retries_after_registration_error", func(t *testing.T) {
		regErr = errors.New("no chain")
		t.Cleanup(func() { regErr = nil })

		m, blocks, ticked := setup(t, ManagerCfg{
			IdleCommitInterval: 6,
		})
		require.ErrorContains(t, m.Start(), "no chain")
		require.NoError(t, m.Start())
		// Success latches. A further Start does not subscribe
		// again.
		require.NoError(t, m.Start())
		defer func() { require.NoError(t, m.Stop()) }()

		chain := m.cfg.Chain.(*mockChainBridge)
		registered := chain.AssertNumberOfCalls(
			t, "RegisterBlockEpochNtfn", 2,
		)
		if !registered {
			return
		}

		blocks <- 1000

		select {
		case <-ticked:
		case <-time.After(testTimeout):
			t.Fatal("no idle tick after registration retry")
		}
	})
}

// idleLoopHarness is a manager whose only job is the block-epoch loop.
// Fetch counts show whether a tick was dispatched.
type idleLoopHarness struct {
	m       *Manager
	blocks  chan int32
	errs    chan error
	fetches *atomic.Int32
}

func newIdleLoopHarness(t *testing.T) *idleLoopHarness {
	t.Helper()

	chain := &mockChainBridge{}
	lookup := &MockAssetLookup{}
	blocks := make(chan int32)
	errs := make(chan error)
	chain.On(
		"RegisterBlockEpochNtfn", mock.Anything,
	).Return(blocks, errs, nil).Once()

	fetches := new(atomic.Int32)
	lookup.On(
		"FetchSupplyCommitAssets", mock.Anything, true,
	).Run(func(mock.Arguments) {
		fetches.Add(1)
	}).Return([]btcec.PublicKey{}, nil).Maybe()

	m := NewManager(ManagerCfg{
		IdleCommitInterval: 6,
		Chain:              chain,
		AssetLookup:        lookup,
	})
	require.NoError(t, m.Start())
	t.Cleanup(func() {
		require.NoError(t, m.Stop())
	})

	return &idleLoopHarness{
		m:       m,
		blocks:  blocks,
		errs:    errs,
		fetches: fetches,
	}
}

// waitIdleLoopExit blocks until the ticker goroutine and its context
// watcher have both left.
func waitIdleLoopExit(t *testing.T, h *idleLoopHarness) {
	t.Helper()

	done := make(chan struct{})
	go func() {
		h.m.Wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("idle tick loop did not exit, fetches=%d",
			h.fetches.Load())
	}
}

// TestIdleTickLoopBlockStream checks that a closed epoch stream is not
// read as a stream of height-0 blocks, while a real height of zero is
// still delivered, and that quit still stops the loop.
func TestIdleTickLoopBlockStream(t *testing.T) {
	t.Parallel()

	t.Run("closed stream", func(t *testing.T) {
		h := newIdleLoopHarness(t)

		// Closing the stream must not be read as height 0.
		// The ticker backs off before resubscribing, so this
		// window observes the hot loop if that check is lost.
		close(h.blocks)
		time.Sleep(idleEpochRetryInitial / 2)
		require.Zero(t, h.fetches.Load())
		require.NoError(t, h.m.Stop())
		waitIdleLoopExit(t, h)
	})

	t.Run("height zero", func(t *testing.T) {
		h := newIdleLoopHarness(t)

		h.blocks <- 0
		require.Eventually(t, func() bool {
			return h.fetches.Load() == 1
		}, time.Second, 5*time.Millisecond)
		require.EqualValues(t, 1, h.fetches.Load())
	})

	t.Run("quit", func(t *testing.T) {
		h := newIdleLoopHarness(t)

		require.NoError(t, h.m.Stop())
		waitIdleLoopExit(t, h)
		require.Zero(t, h.fetches.Load())
	})

	t.Run("epoch error", func(t *testing.T) {
		h := newIdleLoopHarness(t)

		// An error ends the subscription. It must not be read
		// as a block, and the ticker must still shut down.
		h.errs <- errors.New("lost chain")
		time.Sleep(idleEpochRetryInitial / 2)
		require.Zero(t, h.fetches.Load())
		require.NoError(t, h.m.Stop())
		waitIdleLoopExit(t, h)
	})
}

// TestIdleEpochResubscribe checks that a finished block-epoch
// subscription is opened again, that a failed registration waits, and
// that shutdown during that wait leaves the ticker.
func TestIdleEpochResubscribe(t *testing.T) {
	t.Parallel()

	t.Run("resumes after close", func(t *testing.T) {
		assertIdleEpochResumes(t, func(blocks chan int32,
			_ chan error) {

			close(blocks)
		})
	})

	t.Run("resumes after error", func(t *testing.T) {
		assertIdleEpochResumes(t, func(_ chan int32, errs chan error) {
			errs <- errors.New("lost chain")
		})
	})

	t.Run("resumes after error stream close", func(t *testing.T) {
		assertIdleEpochResumes(t, func(_ chan int32, errs chan error) {
			close(errs)
		})
	})

	t.Run("backoff after register failure", func(t *testing.T) {
		chain := &mockChainBridge{}
		lookup := &MockAssetLookup{}
		fetches := new(atomic.Int32)
		lookup.On(
			"FetchSupplyCommitAssets", mock.Anything, true,
		).Run(func(mock.Arguments) {
			fetches.Add(1)
		}).Return([]btcec.PublicKey{}, nil).Maybe()

		firstBlocks := make(chan int32)
		firstErrs := make(chan error)
		chain.On(
			"RegisterBlockEpochNtfn", mock.Anything,
		).Return(firstBlocks, firstErrs, nil).Once()

		var attempts []time.Time
		var mu sync.Mutex
		record := func(mock.Arguments) {
			mu.Lock()
			attempts = append(attempts, time.Now())
			mu.Unlock()
		}
		chain.On(
			"RegisterBlockEpochNtfn", mock.Anything,
		).Run(record).Return(
			nil, nil, errors.New("notifier down"),
		).Once()

		resumed := make(chan int32)
		resumedErrs := make(chan error)
		chain.On(
			"RegisterBlockEpochNtfn", mock.Anything,
		).Run(record).Return(resumed, resumedErrs, nil).Once()

		m := NewManager(ManagerCfg{
			IdleCommitInterval: 6,
			Chain:              chain,
			AssetLookup:        lookup,
		})
		require.NoError(t, m.Start())
		defer func() { require.NoError(t, m.Stop()) }()

		closedAt := time.Now()
		close(firstBlocks)

		require.Eventually(t, func() bool {
			mu.Lock()
			defer mu.Unlock()
			return len(attempts) >= 2
		}, 5*time.Second, 10*time.Millisecond)

		mu.Lock()
		first := attempts[0]
		second := attempts[1]
		mu.Unlock()

		// The failed registration and the successful retry are
		// separated by the grown backoff, and the first attempt
		// itself waits out the initial delay. A retry that keeps
		// the initial delay stays under this gap.
		require.GreaterOrEqual(t, first.Sub(closedAt),
			idleEpochRetryInitial/2)
		gap := second.Sub(first)
		require.GreaterOrEqual(t, gap,
			idleEpochRetryInitial+idleEpochRetryInitial/2)
		require.Less(t, gap, idleEpochRetryMax)

		resumed <- 40
		require.Eventually(t, func() bool {
			return fetches.Load() == 1
		}, time.Second, 5*time.Millisecond)
	})

	t.Run("quit during backoff", func(t *testing.T) {
		h := newIdleLoopHarness(t)

		exited := make(chan struct{})
		go func() {
			h.m.Wg.Wait()
			close(exited)
		}()

		close(h.blocks)
		select {
		case <-exited:
			t.Fatal("ticker exited when the epoch stream closed")
		case <-time.After(idleEpochRetryInitial / 2):
		}

		require.NoError(t, h.m.Stop())
		select {
		case <-exited:
		case <-time.After(2 * time.Second):
			t.Fatal("ticker did not exit on quit during backoff")
		}
		require.Zero(t, h.fetches.Load())
	})

	t.Run("ctx during backoff", func(t *testing.T) {
		chain := &mockChainBridge{}
		chain.On(
			"RegisterBlockEpochNtfn", mock.Anything,
		).Run(func(mock.Arguments) {
			t.Errorf("resubscribed after the ticker context " +
				"was cancelled")
		}).Return(nil, nil, errors.New("should not run")).Maybe()

		m := NewManager(ManagerCfg{
			IdleCommitInterval: 6,
			Chain:              chain,
		})
		ctx, cancel := context.WithCancel(context.Background())
		blocks := make(chan int32)
		errs := make(chan error)

		done := make(chan struct{})
		go func() {
			defer close(done)
			m.idleTickLoop(ctx, blocks, errs, func() {})
		}()

		close(blocks)
		select {
		case <-done:
			t.Fatal("ticker exited when the epoch stream closed")
		case <-time.After(idleEpochRetryInitial / 2):
		}

		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("ticker did not exit on ctx cancel during " +
				"backoff")
		}
	})
}

// assertIdleEpochResumes ends the first epoch subscription and checks
// that a later block on the replacement subscription is ticked.
func assertIdleEpochResumes(t *testing.T, endStream func(chan int32,
	chan error)) {

	t.Helper()

	chain := &mockChainBridge{}
	lookup := &MockAssetLookup{}
	fetches := new(atomic.Int32)
	regs := new(atomic.Int32)
	lookup.On(
		"FetchSupplyCommitAssets", mock.Anything, true,
	).Run(func(mock.Arguments) {
		fetches.Add(1)
	}).Return([]btcec.PublicKey{}, nil).Maybe()

	firstBlocks := make(chan int32)
	firstErrs := make(chan error)
	chain.On(
		"RegisterBlockEpochNtfn", mock.Anything,
	).Run(func(mock.Arguments) {
		regs.Add(1)
	}).Return(firstBlocks, firstErrs, nil).Once()

	nextBlocks := make(chan int32)
	nextErrs := make(chan error)
	chain.On(
		"RegisterBlockEpochNtfn", mock.Anything,
	).Run(func(mock.Arguments) {
		regs.Add(1)
	}).Return(nextBlocks, nextErrs, nil).Once()

	m := NewManager(ManagerCfg{
		IdleCommitInterval: 6,
		Chain:              chain,
		AssetLookup:        lookup,
	})
	require.NoError(t, m.Start())
	defer func() { require.NoError(t, m.Stop()) }()

	endStream(firstBlocks, firstErrs)

	require.Eventually(t, func() bool {
		return regs.Load() >= 2
	}, 5*time.Second, 10*time.Millisecond)

	nextBlocks <- 25
	require.Eventually(t, func() bool {
		return fetches.Load() == 1
	}, time.Second, 5*time.Millisecond)
}

// TestIdleEpochBackoffCap checks that a resubscribe delay grows and then
// stays at the cap.
func TestIdleEpochBackoffCap(t *testing.T) {
	t.Parallel()

	delay := time.Duration(0)
	for i := 0; i < 40; i++ {
		delay = nextIdleEpochBackoff(delay)
		require.LessOrEqual(t, delay, idleEpochRetryMax)
	}
	require.Equal(t, idleEpochRetryMax, delay)
}

// gateStateLog counts FetchState calls and blocks each one until
// release is closed. The block sits inside creation, before the
// machine is cached.
type gateStateLog struct {
	mockStateMachineStore

	calls   atomic.Int32
	release <-chan struct{}
}

// FetchState implements StateMachineStore.
func (g *gateStateLog) FetchState(context.Context, asset.Specifier) (State,
	lfn.Option[SupplyStateTransition], error) {

	g.calls.Add(1)
	<-g.release

	return &DefaultState{}, lfn.None[SupplyStateTransition](), nil
}

// TestFetchStateMachineCreatedOnce checks that two callers asking for
// an uncached group start one state machine. The idle ticker and
// SendEvent share this path. Two callers already raced on main; the
// cache mutex only covers a single Get or Set.
func TestFetchStateMachineCreatedOnce(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	var closed sync.Once
	closeRelease := func() {
		closed.Do(func() { close(release) })
	}
	defer closeRelease()

	groupKey := test.RandPubKey(t)
	spec := asset.NewSpecifierFromGroupKey(*groupKey)

	lookup := &MockAssetLookup{}
	lookup.On(
		"QueryAssetGroupByGroupKey", mock.Anything, mock.Anything,
	).Return(&asset.AssetGroup{
		Genesis: &asset.Genesis{Tag: "once"},
	}, nil).Maybe()
	lookup.On(
		"FetchAssetMetaForAsset", mock.Anything, mock.Anything,
	).Return(&proof.MetaReveal{
		UniverseCommitments: true,
		DelegationKey:       fn.Some(*test.RandPubKey(t)),
	}, nil).Maybe()
	lookup.On(
		"FetchInternalKeyLocator", mock.Anything, mock.Anything,
	).Return(keychain.KeyLocator{}, nil).Maybe()

	stateLog := &gateStateLog{release: release}
	m := NewManager(ManagerCfg{
		AssetLookup:    lookup,
		StateLog:       stateLog,
		DaemonAdapters: newMockDaemonAdapters(),
	})
	require.NoError(t, m.Start())
	defer func() { require.NoError(t, m.Stop()) }()

	var (
		wg         sync.WaitGroup
		sm1, sm2   *StateMachine
		err1, err2 error
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		sm1, err1 = m.fetchStateMachine(spec)
	}()

	// The first caller is held inside creation, before the cache
	// insert. Only then start the second, so it observes the miss.
	require.Eventually(t, func() bool {
		return stateLog.calls.Load() >= 1
	}, time.Second, 5*time.Millisecond)

	go func() {
		defer wg.Done()
		sm2, err2 = m.fetchStateMachine(spec)
	}()

	// Give the second caller time to pass the cache check. It
	// shares the in-flight create, so it must not start another
	// machine. Without that, it calls FetchState too.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if stateLog.calls.Load() > 1 {
			t.Fatalf("created %d state machines while the "+
				"first was still starting",
				stateLog.calls.Load())
		}
		time.Sleep(5 * time.Millisecond)
	}

	closeRelease()
	wg.Wait()

	require.NoError(t, err1)
	require.NoError(t, err2)
	require.EqualValues(t, 1, stateLog.calls.Load())
	require.Same(t, sm1, sm2)

	cached, ok := m.smCache.Get(*groupKey)
	require.True(t, ok)
	require.Same(t, sm1, cached)
}

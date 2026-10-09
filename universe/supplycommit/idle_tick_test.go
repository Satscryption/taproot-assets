package supplycommit

import (
	"errors"
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

	setup := func(t *testing.T, cfg ManagerCfg) (*Manager, chan int32,
		chan struct{}) {

		t.Helper()

		chain := &mockChainBridge{}
		lookup := &MockAssetLookup{}
		stateLog := &mockStateMachineStore{}
		commits := &MockCommitmentTracker{}

		blocks := make(chan int32)
		errs := make(chan error)
		chain.On("RegisterBlockEpochNtfn", mock.Anything).Return(
			blocks, errs, nil,
		).Maybe()

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
		defer func() { require.NoError(t, m.Stop()) }()

		// No epoch registration happens (the mock would fail the send
		// on the unbuffered channel otherwise), and nothing ticks.
		m.cfg.Chain.(*mockChainBridge).AssertNotCalled(
			t, "RegisterBlockEpochNtfn", mock.Anything,
		)
	})

	t.Run("epoch_registration_error", func(t *testing.T) {
		cfg := ManagerCfg{IdleCommitInterval: 6}
		chain := &mockChainBridge{}
		chain.On("RegisterBlockEpochNtfn", mock.Anything).Return(
			nil, nil, errors.New("no chain"),
		).Once()
		cfg.Chain = chain

		m := NewManager(cfg)
		require.ErrorContains(t, m.Start(), "no chain")
	})

}

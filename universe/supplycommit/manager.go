package supplycommit

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/tapnode"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/lightningnetwork/lnd/msgmux"
	"github.com/lightningnetwork/lnd/protofsm"
	"golang.org/x/sync/singleflight"
)

const (
	// DefaultTimeout is the context guard default timeout.
	DefaultTimeout = 30 * time.Second

	// idleEpochRetryInitial is the delay before the first attempt to
	// resubscribe after a block-epoch stream ends, and the base delay
	// after a failed resubscribe. It keeps a dead notifier from turning
	// into a hot loop.
	idleEpochRetryInitial = 200 * time.Millisecond

	// idleEpochRetryMax caps the resubscribe delay. A down notifier
	// backs off, and a later recovery is still picked up.
	idleEpochRetryMax = 30 * time.Second
)

// DaemonAdapters is a wrapper around the protofsm.DaemonAdapters interface
// with the addition of Start and Stop methods.
type DaemonAdapters interface {
	protofsm.DaemonAdapters

	// Start starts the daemon adapters handler service.
	Start() error

	// Stop stops the daemon adapters handler service.
	Stop() error
}

// ManagerCfg is the configuration for the
// Manager. It contains all the dependencies needed to
// manage multiple supply commitment state machines, one for each asset group.
type ManagerCfg struct {
	// AnchoringWatcher is the re-org watcher broadcast commitments
	// register with as speculative anchorings; finalization is then
	// act-gated on burial.
	AnchoringWatcher AnchoringRegistrar

	// AnchoringThreshold is the depth at which a commitment is
	// act-confirmed (buried).
	AnchoringThreshold uint32

	// TreeView is the interface that allows the state machine to obtain an
	// up-to-date snapshot of the root supply tree, and the relevant set of
	// subtrees.
	TreeView SupplyTreeView

	// Commitments is used to track the state of the pre-commitment and
	// commitment outputs that are currently confirmed on-chain.
	Commitments CommitmentTracker

	// Wallet is the interface used interact with the wallet.
	Wallet Wallet

	// AssetLookup is used to look up asset information such as asset groups
	// and asset metadata.
	AssetLookup AssetLookup

	// Signer is used to sign messages with a key specified by a key
	// locator.
	Signer lndclient.SignerClient

	// KeyRing is the key ring used to derive new keys.
	KeyRing KeyRing

	// Chain is our access to the current main chain.
	//
	// TODO(roasbeef): can make a slimmer version of
	Chain tapnode.ChainBridge

	// SupplySyncer is used to insert supply commitments into the remote
	// universe server.
	SupplySyncer SupplySyncer

	// DaemonAdapters is a set of adapters that allow the state machine to
	// interact with external daemons whilst processing internal events.
	DaemonAdapters DaemonAdapters

	// StateLog is the main state log that is used to track the state of the
	// state machine. This is used to persist the state of the state machine
	// across restarts.
	StateLog StateMachineStore

	// ChainParams is the chain parameters for the chain that we're
	// operating on.
	ChainParams chaincfg.Params

	// IgnoreCheckerCache is used to invalidate the ignore cache when a new
	// supply commitment is created.
	IgnoreCheckerCache IgnoreCheckerCache

	// IdleCommitInterval is the number of blocks after which a locally
	// controlled asset group with a confirmed supply commitment
	// automatically publishes an ancestry-linked successor commitment, even
	// if there are no new supply updates. Zero disables idle successors.
	IdleCommitInterval uint32

	// AutoPublishPending, if true, automatically publishes pending supply
	// updates when the next block arrives, instead of waiting for a manual
	// UpdateSupplyCommit call.
	AutoPublishPending bool
}

// autoCommitEnabled returns true if the manager should emit an idle tick for
// every new block.
func (c *ManagerCfg) autoCommitEnabled() bool {
	return c.IdleCommitInterval > 0 || c.AutoPublishPending
}

// Manager is a manager for multiple supply commitment state
// machines, one for each asset group. It is responsible for starting and
// stopping the state machines, as well as forwarding sending events to them.
type Manager struct {
	// cfg is the configuration for the multi state machine manager.
	cfg ManagerCfg

	// smCache is a cache that maps asset group public keys to their
	// supply commitment state machines.
	smCache *stateMachineCache

	// ContextGuard provides a wait group and main quit channel that can be
	// used to create guarded contexts.
	*fn.ContextGuard

	// startMu serializes Start. Registration failure must stay
	// retryable: a sync.Once would consume the attempt, and a later
	// Start would report success without subscribing.
	startMu sync.Mutex

	// started is true once Start has completed without error. Further
	// Start calls are then a no-op.
	started bool

	stopOnce sync.Once

	// smFlight collapses concurrent creates of one group into a single
	// call. The cache mutex covers one map operation, so two callers
	// can otherwise both miss and start a machine from the same
	// durable state. Different groups still create in parallel.
	smFlight singleflight.Group
}

// NewManager creates a new multi state machine manager.
func NewManager(cfg ManagerCfg) *Manager {
	return &Manager{
		cfg: cfg,
		ContextGuard: &fn.ContextGuard{
			DefaultTimeout: DefaultTimeout,
			Quit:           make(chan struct{}),
		},
	}
}

// Start starts the multi state machine manager. When idle successors or
// automatic publishing is enabled, Start registers for block epochs and
// launches the idle ticker. A failed registration is returned and is not
// latched, so a later Start retries it. Once Start has succeeded, further
// calls are a no-op. A stream that later closes or errors is resubscribed
// from that same goroutine, with a capped backoff.
func (m *Manager) Start() error {
	m.startMu.Lock()
	defer m.startMu.Unlock()

	if m.started {
		return nil
	}

	// The cache is created even when registration fails, so Stop can
	// run after a failed Start. A retry must not replace it: a caller
	// may already have stored a machine there.
	if m.smCache == nil {
		m.smCache = newStateMachineCache()
	}

	// If idle successors or automatic publishing is enabled, we need
	// to tick the state machines as new blocks arrive.
	if !m.cfg.autoCommitEnabled() {
		m.started = true
		return nil
	}

	ctx, cancel := m.WithCtxQuitNoTimeout()
	blockChan, errChan, subCancel, err := m.registerBlockEpoch(ctx)
	if err != nil {
		cancel()
		return fmt.Errorf("unable to register for block epochs: %w",
			err)
	}

	log.Infof("Supply commit idle ticker enabled "+
		"(idle_commit_interval=%d blocks, "+
		"auto_publish_pending=%v)", m.cfg.IdleCommitInterval,
		m.cfg.AutoPublishPending)

	m.Wg.Add(1)
	go func() {
		defer m.Wg.Done()
		defer cancel()

		m.idleTickLoop(ctx, blockChan, errChan, subCancel)
	}()

	m.started = true
	return nil
}

// registerBlockEpoch subscribes to block epochs with a child context so
// the subscription can be dropped without stopping the ticker.
func (m *Manager) registerBlockEpoch(ctx context.Context) (
	chan int32, chan error, func(), error) {

	subCtx, subCancel := context.WithCancel(ctx)
	blockChan, errChan, err := m.cfg.Chain.RegisterBlockEpochNtfn(subCtx)
	if err != nil {
		subCancel()
		return nil, nil, nil, err
	}

	return blockChan, errChan, subCancel, nil
}

// idleTickLoop sends an IdleTickEvent for every new block. When the epoch
// stream ends it resubscribes until the manager is shutting down. The
// same goroutine owns every subscription, so a restart cannot start a
// second ticker.
func (m *Manager) idleTickLoop(ctx context.Context, blockChan chan int32,
	errChan chan error, subCancel func()) {

	// subCancel is reassigned as subscriptions are replaced. The defer
	// must call whatever cancel is current when the loop leaves.
	defer func() { subCancel() }()

	for {
		if !m.serveIdleEpoch(ctx, blockChan, errChan) {
			return
		}

		// The stream is dead. Drop it before opening another so
		// two subscriptions are not live together.
		subCancel()

		var err error
		blockChan, errChan, subCancel, err = m.resubscribeBlockEpoch(
			ctx,
		)
		if err != nil {
			return
		}
	}
}

// serveIdleEpoch reads one block-epoch subscription. It returns true
// when that subscription ended and the ticker should resubscribe, and
// false when the manager is shutting down. A closed channel is a single
// end-of-stream signal, not a series of height-0 blocks.
func (m *Manager) serveIdleEpoch(ctx context.Context, blockChan chan int32,
	errChan chan error) bool {

	for {
		select {
		case height, ok := <-blockChan:
			if !ok {
				log.Infof("Supply commit idle ticker block " +
					"epoch stream closed, resubscribing")
				return true
			}
			if height < 0 {
				continue
			}

			m.sendIdleTicks(ctx, uint32(height))

		case err, ok := <-errChan:
			// A closed error stream is the same end-of-stream
			// signal as a closed block stream. One receive
			// leaves the loop; it must not spin.
			if !ok {
				log.Infof("Supply commit idle ticker block " +
					"epoch error stream closed, " +
					"resubscribing")
				return true
			}
			if err != nil {
				log.Errorf("Supply commit idle ticker block "+
					"epoch subscription failed, "+
					"resubscribing: %v", err)
			}

			return true

		case <-ctx.Done():
			return false

		case <-m.Quit:
			return false
		}
	}
}

// resubscribeBlockEpoch opens a new block-epoch subscription. Each
// attempt waits with a capped backoff so a notifier that is still down
// cannot be polled in a loop. The wait returns when the manager shuts
// down.
func (m *Manager) resubscribeBlockEpoch(ctx context.Context) (
	chan int32, chan error, func(), error) {

	backoff := idleEpochRetryInitial
	for {
		if err := m.waitIdleEpochRetry(ctx, backoff); err != nil {
			return nil, nil, func() {}, err
		}

		blockChan, errChan, subCancel, err := m.registerBlockEpoch(ctx)
		if err != nil {
			log.Errorf("Supply commit idle ticker failed to "+
				"resubscribe for block epochs: %v", err)
			backoff = nextIdleEpochBackoff(backoff)
			continue
		}

		log.Infof("Supply commit idle ticker resubscribed for " +
			"block epochs")

		return blockChan, errChan, subCancel, nil
	}
}

// waitIdleEpochRetry blocks for delay, or until the ticker context or
// the manager quit signal fires.
func (m *Manager) waitIdleEpochRetry(ctx context.Context,
	delay time.Duration) error {

	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-timer.C:
		return nil

	case <-ctx.Done():
		return ctx.Err()

	case <-m.Quit:
		return errors.New("supply commit idle ticker shutting down")
	}
}

// nextIdleEpochBackoff grows a resubscribe delay and caps it so the
// wait cannot run away.
func nextIdleEpochBackoff(current time.Duration) time.Duration {
	if current < idleEpochRetryInitial {
		return idleEpochRetryInitial
	}

	next := current * 2
	if next > idleEpochRetryMax || next < current {
		return idleEpochRetryMax
	}

	return next
}

// sendIdleTicks sends an idle tick for the given block height to all locally
// controlled supply commit asset groups. Errors are logged, a single failing
// group must not stop the others.
func (m *Manager) sendIdleTicks(ctx context.Context, height uint32) {
	groupKeys, err := m.cfg.AssetLookup.FetchSupplyCommitAssets(ctx, true)
	if err != nil {
		log.Errorf("Unable to fetch supply commit assets for idle "+
			"tick at height %d: %v", height, err)

		return
	}

	for idx := range groupKeys {
		groupKey := groupKeys[idx]
		assetSpec := asset.NewSpecifierFromGroupKey(groupKey)

		sm, err := m.fetchStateMachine(assetSpec)
		if err != nil {
			log.Errorf("Unable to get state machine for idle "+
				"tick (asset=%s, height=%d): %v",
				assetSpec.String(), height, err)

			continue
		}

		// SendEvent blocks while the state machine is busy, so make
		// sure we don't hang forever.
		sendCtx, cancel := context.WithTimeout(ctx, DefaultTimeout)
		sm.SendEvent(sendCtx, &IdleTickEvent{BlockHeight: height})
		cancel()
	}
}

// Stop stops the multi state machine manager, which in turn stops all asset
// group key specific supply commitment state machines.
func (m *Manager) Stop() error {
	m.stopOnce.Do(func() {
		// Cancel the state machine context to signal all state machines
		// to stop.
		close(m.Quit)

		// Stop all state machines.
		m.smCache.StopAll()
	})

	return nil
}

// startAssetSM creates and starts a new supply commitment state
// machine for the given asset specifier.
func (m *Manager) startAssetSM(ctx context.Context,
	assetSpec asset.Specifier) (*StateMachine, error) {

	env := &Environment{
		AssetSpec:          assetSpec,
		TreeView:           m.cfg.TreeView,
		Commitments:        m.cfg.Commitments,
		Wallet:             m.cfg.Wallet,
		AssetLookup:        m.cfg.AssetLookup,
		KeyRing:            m.cfg.KeyRing,
		Chain:              m.cfg.Chain,
		SupplySyncer:       m.cfg.SupplySyncer,
		StateLog:           m.cfg.StateLog,
		CommitConfTarget:   DefaultCommitConfTarget,
		ChainParams:        m.cfg.ChainParams,
		IgnoreCheckerCache: m.cfg.IgnoreCheckerCache,
		AnchoringWatcher:   m.cfg.AnchoringWatcher,
		AnchoringThreshold: m.cfg.AnchoringThreshold,
		IdleCommitInterval: m.cfg.IdleCommitInterval,
		AutoPublishPending: m.cfg.AutoPublishPending,
	}

	// Before we start the state machine, we'll need to fetch the current
	// state from disk, to see if we need to emit any new events.
	initialState, initialTransition, err := m.cfg.StateLog.FetchState(
		ctx, assetSpec,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch current state: %w", err)
	}

	// The durable record keeps the state name and the pending
	// transition apart. A resumed state that carries the transition in
	// memory is rehydrated from it; its handlers would otherwise run
	// against an empty transition, and a broadcast state's first event
	// would kill the machine over a nil commitment transaction.
	initialTransition.WhenSome(func(transition SupplyStateTransition) {
		if state, ok := initialState.(*CommitBroadcastState); ok {
			state.SupplyTransition = transition
		}
	})

	// A restored broadcast state must hold its anchoring before the
	// machine resumes and rests on it. A record persisted before the
	// watcher existed has none; adopt it now. The state it watches
	// over is already durable, so the registration stakes nothing.
	if broadcast, ok := initialState.(*CommitBroadcastState); ok &&
		broadcast.SupplyTransition.NewCommitment.Txn != nil {

		registered, err := registerCommitAnchoring(
			ctx, env, &broadcast.SupplyTransition,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to adopt commit "+
				"anchoring: %w", err)
		}
		if registered {
			log.Infof("Registered missing commit anchoring for "+
				"group %v on restart", assetSpec)
		}
	}

	// Create a new error reporter for the state machine.
	errorReporter := NewErrorReporter(assetSpec)

	fsmCfg := protofsm.StateMachineCfg[Event, *Environment]{
		ErrorReporter: &errorReporter,
		InitialState:  initialState,
		Env:           env,
		Daemon:        m.cfg.DaemonAdapters,
	}
	newSm := protofsm.NewStateMachine[Event, *Environment](fsmCfg)

	// Ensure that the state machine is running. We use the manager's
	// context guard to derive a sub context which will be cancelled when
	// the manager is stopped.
	smCtx, _ := m.WithCtxQuitNoTimeout()
	newSm.Start(smCtx)

	// Assert that the state machine is running. Start should block until
	// the state machine is running.
	if !newSm.IsRunning() {
		return nil, fmt.Errorf("state machine unexpectadly not running")
	}

	// If specific initial states are provided, we send the corresponding
	// events to the state machine to ensure it begins ticking as expected.
	switch state := initialState.(type) {
	// Once we write the commitment transaction to disk in CommitTxSign,
	// then on restart, we'll be in the broadcast state. The broadcast
	// event re-publishes the persisted transaction: the record is
	// written before the publish, so a crash between the two, or a
	// publish the wallet rejected, would otherwise leave a signed
	// transaction nobody broadcasts and a group that can never
	// advance. Publishing a transaction the network already has is
	// harmless. The re-org watcher already holds the commitment and
	// finalizes it out of band, so a tick follows: the resting
	// handler re-derives the machine's position from the durable
	// record. Rows persisted by the legacy finalize state load as
	// this state too — a pending transition awaiting act-level
	// finality is exactly what the broadcast state means.
	case *CommitBroadcastState:
		if state.SupplyTransition.NewCommitment.Txn != nil {
			newSm.SendEvent(ctx, &BroadcastEvent{})
		}
		newSm.SendEvent(ctx, &CommitTickEvent{})

	// The watcher's finalizer and compensator park bound updates here
	// for the machine to pick up, so a tick resumes the interrupted
	// cycle.
	case *UpdatesPendingState:
		newSm.SendEvent(ctx, &CommitTickEvent{})
	}

	return &newSm, nil
}

// fetchStateMachine retrieves a state machine from the cache or creates a
// new one if it doesn't exist. If a new state machine is created, it is also
// started.
func (m *Manager) fetchStateMachine(
	assetSpec asset.Specifier) (*StateMachine, error) {

	groupKey, err := assetSpec.UnwrapGroupKeyOrErr()
	if err != nil {
		return nil, fmt.Errorf("asset specifier missing group key: %w",
			err)
	}

	// Fast path: the usual case is a machine that is already running.
	if sm, ok := m.runningMachine(*groupKey); ok {
		return sm, nil
	}

	// Creation reads the durable state and starts a goroutine. Share
	// that work per group so a second caller, including the idle
	// ticker, adopts the machine instead of starting another from the
	// same state.
	flightKey := string(groupKey.SerializeCompressed())
	created, err, _ := m.smFlight.Do(flightKey, func() (any, error) {
		return m.createStateMachine(assetSpec, groupKey)
	})
	if err != nil {
		return nil, err
	}

	return created.(*StateMachine), nil
}

// createStateMachine returns the running machine for the group, creating
// and caching one when none is running. Callers must already be inside
// smFlight for this group so two creates cannot overlap.
func (m *Manager) createStateMachine(assetSpec asset.Specifier,
	groupKey *btcec.PublicKey) (*StateMachine, error) {

	// Re-check under the flight. A caller that lost the race finds
	// the winner's machine here.
	if sm, ok := m.runningMachine(*groupKey); ok {
		return sm, nil
	}

	// Nothing running is cached (a stopped machine falls through).
	// Before creating one, ensure that the asset group supports supply
	// commitments. If it doesn't, then we return an error.
	ctx, cancel := m.WithCtxQuitNoTimeout()
	defer cancel()

	err := CheckSupplyCommitSupport(
		ctx, m.cfg.AssetLookup, assetSpec, true,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to ensure supply commit "+
			"support for asset: %w", err)
	}

	// Start the state machine and add it to the cache.
	newSm, err := m.startAssetSM(ctx, assetSpec)
	if err != nil {
		return nil, fmt.Errorf("unable to start state machine: %w",
			err)
	}

	m.smCache.Set(*groupKey, newSm)

	return newSm, nil
}

// runningMachine returns the cached state machine for the group when it
// exists and is running.
func (m *Manager) runningMachine(groupKey btcec.PublicKey) (*StateMachine,
	bool) {

	sm, ok := m.smCache.Get(groupKey)
	if !ok || !sm.IsRunning() {
		return nil, false
	}

	return sm, true
}

// SendEvent sends an event to the state machine associated with the given asset
// specifier. If a state machine for the asset group does not exist, it will be
// created and started.
func (m *Manager) SendEvent(ctx context.Context,
	assetSpec asset.Specifier, event Event) error {

	sm, err := m.fetchStateMachine(assetSpec)
	if err != nil {
		return fmt.Errorf("unable to get or create state machine: %w",
			err)
	}

	sm.SendEvent(ctx, event)
	return nil
}

// IgnoreAssetOutPoint allows an asset issuer to mark a specific asset outpoint
// as ignored. An ignored outpoint will be included in the next universe
// commitment transaction that is published.
func (m *Manager) IgnoreAssetOutPoint(ctx context.Context,
	assetSpec asset.Specifier, assetAnchorPoint asset.AnchorPoint,
	amount uint64) (universe.SignedIgnoreTuple, error) {

	var zero universe.SignedIgnoreTuple

	assetID, err := assetSpec.UnwrapIdOrErr()
	if err != nil {
		return zero, err
	}

	// Fetch the asset group for the given asset ID. If a group key was
	// provided, use it for verification; otherwise, fall back to this
	// group key.
	assetGroup, err := m.cfg.AssetLookup.QueryAssetGroupByID(ctx, assetID)
	if err != nil {
		return zero, fmt.Errorf("failed to find asset group given "+
			"asset ID: %w", err)
	}

	// If the asset specifier includes a group key, ensure it matches the
	// group key of the asset group fetched from the database.
	if assetSpec.HasGroupPubKey() {
		givenGroupKey, err := assetSpec.UnwrapGroupKeyOrErr()
		if err != nil {
			return zero, err
		}

		if !assetGroup.GroupKey.GroupPubKey.IsEqual(givenGroupKey) {
			return zero, fmt.Errorf("provided group key does " +
				"not match asset group")
		}
	}

	// Formulate an asset specifier from the asset ID and group key.
	assetSpec = asset.NewSpecifierOptionalGroupKey(
		assetID, assetGroup.GroupKey,
	)

	// Check that the asset supports supply commitments. While the signing
	// step would also fail without support, performing this check here
	// provides a clearer error and makes the assumption explicit.
	err = CheckSupplyCommitSupport(ctx, m.cfg.AssetLookup, assetSpec, true)
	if err != nil {
		return zero, fmt.Errorf("asset does not support supply "+
			"commitments: %w", err)
	}

	// Retrieve asset meta reveal for the asset ID. This will be used to
	// obtain the supply commitment delegation key.
	metaReveal, err := m.cfg.AssetLookup.FetchAssetMetaForAsset(
		ctx, assetID,
	)
	if err != nil {
		return zero, fmt.Errorf("failed to fetch asset meta: %w", err)
	}

	// Extract supply commitment delegation pub key from the asset metadata.
	delegationPubKey, err := metaReveal.DelegationKey.UnwrapOrErr(
		fmt.Errorf("delegation key not found for given asset"),
	)
	if err != nil {
		return zero, err
	}

	// Fetch the delegation key locator.
	delegationKeyLoc, err := m.cfg.AssetLookup.FetchInternalKeyLocator(
		ctx, &delegationPubKey,
	)
	switch {
	case errors.Is(err, address.ErrInternalKeyNotFound):
		return zero, fmt.Errorf("delegation key locator not found; " +
			"only delegation key owners can ignore asset " +
			"outpoints for this asset group")
	case err != nil:
		return zero, fmt.Errorf("failed to fetch delegation key "+
			"locator: %w", err)
	}

	// Determine the current block height and add it to the ignore tuple.
	// A supply commitment verifier can then validate each commitment
	// against historical snapshots of the supply subtrees.
	currentBlockHeight, err := m.cfg.Chain.CurrentHeight(ctx)
	if err != nil {
		return zero, fmt.Errorf("failed to get current block height "+
			"for new ignore tuple: %w", err)
	}

	// Formulate the ignore entry and sign it with the delegation key.
	ignoreTuple := universe.IgnoreTuple{
		PrevID:      assetAnchorPoint,
		Amount:      amount,
		BlockHeight: currentBlockHeight,
	}

	signedIgnore, err := ignoreTuple.GenSignedIgnore(
		ctx, m.cfg.Signer, delegationKeyLoc,
	)
	if err != nil {
		return zero, fmt.Errorf("failed to sign ignore tuple: %w", err)
	}

	// Upsert a signed ignore tuple into the ignore tree archive and
	// get back the authenticated ignore tuples.
	ignoreEvent := NewIgnoreEvent{
		SignedIgnoreTuple: signedIgnore,
	}
	err = m.SendEventSync(ctx, assetSpec, &ignoreEvent)
	if err != nil {
		return zero, fmt.Errorf("failed to upsert ignore tuple: %w",
			err)
	}

	return signedIgnore, nil
}

// SendEventSync sends an event to the state machine and waits for it to be
// processed and written to disk. This method provides synchronous confirmation
// that the event has been durably persisted. If the event doesn't support
// synchronous processing (i.e., it's not a SupplyUpdateEvent), this method will
// return an error.
func (m *Manager) SendEventSync(ctx context.Context, assetSpec asset.Specifier,
	event SyncSupplyUpdateEvent) error {

	// Only SupplyUpdateEvents can be processed synchronously.
	supplyEvent, ok := event.(SupplyUpdateEvent)
	if !ok {
		return fmt.Errorf("event type %T does not support "+
			"synchronous processing", event)
	}

	// We'll use this channel to signal when the event has been processed.
	done := make(chan error, 1)

	// As the event has already been created, we'll set the done channel
	// directly.
	switch e := supplyEvent.(type) {
	case *NewMintEvent:
		e.Done = done
	case *NewBurnEvent:
		e.Done = done
	case *NewIgnoreEvent:
		e.Done = done
	default:
		return fmt.Errorf("unexpected supply update event type: %T",
			supplyEvent)
	}

	// Send the event to the state machine, the pause and wait until it
	// signals that the event has been fully processed.
	if err := m.SendEvent(ctx, assetSpec, supplyEvent); err != nil {
		return err
	}
	return event.WaitForDone(ctx)
}

// SendMintEvent sends a mint event to the supply commitment state machine.
//
// NOTE: This is consumed by the GenesisAugmenter at batch confirmation
// time via the MintEventEmitter interface.
func (m *Manager) SendMintEvent(ctx context.Context, assetSpec asset.Specifier,
	leafKey universe.UniqueLeafKey, issuanceProof universe.Leaf,
	mintBlockHeight uint32) error {

	mintEvent := &NewMintEvent{
		LeafKey:       leafKey,
		IssuanceProof: issuanceProof,
		MintHeight:    mintBlockHeight,
	}

	return m.SendEventSync(ctx, assetSpec, mintEvent)
}

// SendBurnEvent sends a burn event to the supply commitment state machine.
//
// NOTE: This implements the tapfreighter.BurnSupplyCommitter interface.
func (m *Manager) SendBurnEvent(ctx context.Context, assetSpec asset.Specifier,
	burnLeaf universe.BurnLeaf) error {

	burnEvent := &NewBurnEvent{
		BurnLeaf: burnLeaf,
	}

	return m.SendEventSync(ctx, assetSpec, burnEvent)
}

// StartSupplyPublishFlow triggers the state machine to build and publish
// a new supply commitment if pending supply tree updates exist.
func (m *Manager) StartSupplyPublishFlow(ctx context.Context,
	assetSpec asset.Specifier) error {

	sm, err := m.fetchStateMachine(assetSpec)
	if err != nil {
		return fmt.Errorf("unable to get or create state machine: %w",
			err)
	}

	sm.SendEvent(ctx, &CommitTickEvent{})
	return nil
}

// CanHandle determines if the state machine associated with the given asset
// specifier can handle the given message. If a state machine for the asset
// group does not exist, it will be created and started.
func (m *Manager) CanHandle(assetSpec asset.Specifier,
	msg msgmux.PeerMsg) (bool, error) {

	sm, err := m.fetchStateMachine(assetSpec)
	if err != nil {
		return false, fmt.Errorf("unable to get or create state "+
			"machine: %w", err)
	}

	return sm.CanHandle(msg), nil
}

// Name returns the name of the state machine associated with the given asset
// specifier. If a state machine for the asset group does not exist, it will be
// created and started.
func (m *Manager) Name(
	assetSpec asset.Specifier) (string, error) {

	sm, err := m.fetchStateMachine(assetSpec)
	if err != nil {
		return "", fmt.Errorf("unable to get or create state "+
			"machine: %w", err)
	}

	return sm.Name(), nil
}

// SendMessage sends a message to the state machine associated with the given
// asset specifier. If a state machine for the asset group does not exist, it
// will be created and started.
func (m *Manager) SendMessage(ctx context.Context,
	assetSpec asset.Specifier, msg msgmux.PeerMsg) (bool, error) {

	sm, err := m.fetchStateMachine(assetSpec)
	if err != nil {
		return false, fmt.Errorf("unable to get or create state "+
			"machine: %w", err)
	}

	return sm.SendMessage(ctx, msg), nil
}

// CurrentState returns the current state of the state machine associated with
// the given asset specifier. If a state machine for the asset group does not
// exist, it will be created and started.
func (m *Manager) CurrentState(assetSpec asset.Specifier) (
	protofsm.State[Event, *Environment], error) {

	sm, err := m.fetchStateMachine(assetSpec)
	if err != nil {
		return nil, fmt.Errorf("unable to get or create state "+
			"machine: %w", err)
	}

	return sm.CurrentState()
}

// RegisterStateEvents registers a state event subscriber with the state machine
// associated with the given asset specifier. If a state machine for the asset
// group does not exist, it will be created and started.
func (m *Manager) RegisterStateEvents(
	assetSpec asset.Specifier) (StateSub, error) {

	sm, err := m.fetchStateMachine(assetSpec)
	if err != nil {
		return nil, fmt.Errorf("unable to get or create state "+
			"machine: %w", err)
	}

	return sm.RegisterStateEvents(), nil
}

// RemoveStateSub removes a state event subscriber from the state machine
// associated with the given asset specifier. If a state machine for the asset
// group does not exist, it will be created and started.
func (m *Manager) RemoveStateSub(assetSpec asset.Specifier,
	sub StateSub) error {

	sm, err := m.fetchStateMachine(assetSpec)
	if err != nil {
		return fmt.Errorf("unable to get or create state "+
			"machine: %w", err)
	}

	sm.RemoveStateSub(sub)

	return nil
}

// FetchCommitmentResp is the response type for the FetchCommitment method.
type FetchCommitmentResp struct {
	// SupplyTree is the supply tree for an asset. The leaves of this tree
	// commit to the roots of the supply commit subtrees.
	SupplyTree mssmt.Tree

	// Subtrees maps a subtree type to its corresponding supply subtree.
	Subtrees SupplyTrees

	// ChainCommitment links the supply tree to its anchor transaction.
	ChainCommitment RootCommitment
}

// FetchSupplyLeavesByHeight returns the set of supply leaves for the given
// asset specifier within the specified height range.
func (m *Manager) FetchSupplyLeavesByHeight(
	ctx context.Context, assetSpec asset.Specifier, startHeight,
	endHeight uint32) (SupplyLeaves, error) {

	var zero SupplyLeaves

	resp, err := m.cfg.TreeView.FetchSupplyLeavesByHeight(
		ctx, assetSpec, startHeight, endHeight,
	).Unpack()
	if err != nil {
		return zero, fmt.Errorf("unable to fetch supply leaves: %w",
			err)
	}

	return resp, nil
}

// FetchSubTrees returns all the sub trees for the given asset specifier.
func (m *Manager) FetchSubTrees(ctx context.Context,
	assetSpec asset.Specifier,
	blockHeightEnd fn.Option[uint32]) (SupplyTrees, error) {

	var zero SupplyTrees

	subtrees, err := m.cfg.TreeView.FetchSubTrees(
		ctx, assetSpec, blockHeightEnd,
	).Unpack()
	if err != nil {
		return zero, fmt.Errorf("unable to fetch sub trees: %w", err)
	}

	return subtrees, nil
}

// stateMachineCache is a thread-safe cache mapping an asset group's public key
// to its supply commitment state machine.
type stateMachineCache struct {
	// mu is a mutex that is used to synchronize access to the cache.
	mu sync.RWMutex

	// cache is a map of serialized asset group public keys to their
	// supply commitment state machines.
	cache map[asset.SerializedKey]*StateMachine
}

// newStateMachineCache creates a new supply commit state machine cache.
func newStateMachineCache() *stateMachineCache {
	return &stateMachineCache{
		cache: make(map[asset.SerializedKey]*StateMachine),
	}
}

// StopAll stops all state machines in the cache.
func (c *stateMachineCache) StopAll() {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Iterate over the cache and append each state machine to the slice.
	for _, sm := range c.cache {
		// Sanity check: ensure sm is not nil.
		if sm == nil {
			continue
		}

		// Stop the state machine.
		sm.Stop()
	}
}

// Get retrieves a state machine from the cache.
func (c *stateMachineCache) Get(groupPubKey btcec.PublicKey) (*StateMachine,
	bool) {

	// Serialize the group key.
	serializedGroupKey := asset.ToSerialized(&groupPubKey)

	c.mu.RLock()
	defer c.mu.RUnlock()

	sm, ok := c.cache[serializedGroupKey]
	return sm, ok
}

// Set adds a state machine to the cache.
func (c *stateMachineCache) Set(groupPubKey btcec.PublicKey, sm *StateMachine) {
	// Serialize the group key.
	serializedGroupKey := asset.ToSerialized(&groupPubKey)

	c.mu.Lock()
	defer c.mu.Unlock()

	// If the state machine already exists, return without updating it.
	// This helps to ensure that we always have a pointer to every state
	// machine in the cache, even if it is not currently active.
	if _, exists := c.cache[serializedGroupKey]; exists {
		return
	}

	c.cache[serializedGroupKey] = sm
}

// Delete removes a state machine from the cache.
func (c *stateMachineCache) Delete(groupPubKey btcec.PublicKey) {
	// Serialize the group key.
	serializedGroupKey := asset.ToSerialized(&groupPubKey)

	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.cache, serializedGroupKey)
}

// ErrorReporter is an asset specific error reporter that can be used to
// report errors that occur during the operation of the asset group supply
// commitment state machine.
type ErrorReporter struct {
	// assetSpec is the asset specifier that identifies the asset group.
	assetSpec asset.Specifier
}

// NewErrorReporter creates a new ErrorReporter for the given asset specifier
// state machine.
func NewErrorReporter(assetSpec asset.Specifier) ErrorReporter {
	return ErrorReporter{
		assetSpec: assetSpec,
	}
}

// ReportError reports an error that occurred during the operation of the
// asset group supply commitment state machine.
func (r *ErrorReporter) ReportError(err error) {
	log.Errorf("supply commit state machine (asset_spec=%s): %v",
		r.assetSpec.String(), err)
}

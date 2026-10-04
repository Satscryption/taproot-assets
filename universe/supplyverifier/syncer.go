package supplyverifier

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/lightninglabs/taproot-assets/universe/supplycommit"
)

const (
	// defaultPullTimeout is the default timeout for a supply commitment
	// pull. Fetch retries run under this deadline.
	defaultPullTimeout = 30 * time.Second

	// maxAncestorChain is the most predecessor supply commitments one
	// push will load and insert. The walk also stops on a repeated
	// outpoint and on context cancellation. A longer gap is not
	// partially inserted: the push fails and a later attempt retries
	// the same chain from the start.
	maxAncestorChain = 256
)

// errSupplyChainRemainder is returned when a gap is longer than
// maxAncestorChain. It is not inserted as a prefix: the server is left
// unchanged by this repair, and the caller's retry walks the same chain.
var errSupplyChainRemainder = errors.New("supply commitment predecessor " +
	"chain exceeds the repair limit")

// errNoSupplySyncAttempt is returned when a retry budget admits no
// call. Callers treat a nil error as a completed sync, so skipping the
// call must not report success.
var errNoSupplySyncAttempt = errors.New("supply sync retry made no attempt")

// UniverseClient is an interface that represents a client connection to a
// remote universe server.
type UniverseClient interface {
	// InsertSupplyCommit inserts a supply commitment for a specific
	// asset group into the remote universe server.
	InsertSupplyCommit(ctx context.Context, assetSpec asset.Specifier,
		commitment supplycommit.RootCommitment,
		updateLeaves supplycommit.SupplyLeaves,
		chainProof supplycommit.ChainProof) error

	// FetchSupplyCommit fetches a supply commitment for a specific
	// asset group from the remote universe server.
	FetchSupplyCommit(ctx context.Context, assetSpec asset.Specifier,
		spentCommitOutpoint fn.Option[wire.OutPoint]) (
		supplycommit.FetchSupplyCommitResult, error)

	// Close closes the fetcher and cleans up any resources.
	Close() error
}

// UniverseClientFactory is a function type that creates UniverseClient
// instances for a given universe server address.
type UniverseClientFactory func(serverAddr universe.ServerAddr) (UniverseClient,
	error)

// SupplySyncerStore is an interface for storing synced leaves and state.
type SupplySyncerStore interface {
	// LogSupplyCommitPush logs that a supply commitment and its leaves
	// have been successfully pushed to a remote universe server.
	LogSupplyCommitPush(ctx context.Context, serverAddr universe.ServerAddr,
		assetSpec asset.Specifier,
		commitment supplycommit.RootCommitment,
		leaves supplycommit.SupplyLeaves) error

	// FetchPushedServers returns the addresses of the servers the
	// given supply commitment has already been pushed to, as
	// recorded by LogSupplyCommitPush.
	FetchPushedServers(ctx context.Context, assetSpec asset.Specifier,
		commitment supplycommit.RootCommitment) ([]string, error)
}

// UniverseFederationView is an interface that provides a view of the
// federation of universe servers.
type UniverseFederationView interface {
	// UniverseServers returns a list of all known universe servers in
	// the federation.
	UniverseServers(ctx context.Context) ([]universe.ServerAddr, error)
}

// SupplyCommitHistory loads a supply commitment this node already
// stores, including the leaves and chain proof needed to push it. The
// outpoint is the commitment output a successor spends.
type SupplyCommitHistory interface {
	// FetchSupplyCommitPush returns the push payload for the supply
	// commitment that created outpoint.
	FetchSupplyCommitPush(ctx context.Context, assetSpec asset.Specifier,
		outpoint wire.OutPoint) (supplycommit.RootCommitment,
		supplycommit.SupplyLeaves, supplycommit.ChainProof, error)
}

// SupplySyncerConfig is a configuration struct for creating a new
// SupplySyncer instance.
type SupplySyncerConfig struct {
	// ClientFactory is a factory function that creates UniverseClient
	// instances for specific universe server addresses.
	ClientFactory UniverseClientFactory

	// Store is used to persist supply leaves to the local database.
	Store SupplySyncerStore

	// UniverseFederationView is used to fetch the list of known
	// universe servers in the federation.
	UniverseFederationView UniverseFederationView

	// History loads predecessor supply commitments when a server
	// rejects an insert because it has not seen the spent commitment.
	// A nil History leaves that rejection unrepaired.
	History SupplyCommitHistory

	// Retry overrides backoff for universe dial, fetch, and insert.
	// Nil selects fn.DefaultRetryConfig: 10 retries after the first
	// attempt, starting at 100ms and doubling up to 5s. Cancellation
	// of the context ends the sequence. ErrCommitmentNotFound and
	// ErrPrevCommitmentNotFound are returned on the first occurrence
	// instead of being retried. A negative MaxRetries is clamped to
	// zero so the first attempt still runs.
	Retry *fn.RetryConfig
}

// SupplySyncer is a struct that is responsible for retrieving supply leaves
// from a universe.
type SupplySyncer struct {
	// cfg is the configuration for the SupplySyncer.
	cfg SupplySyncerConfig
}

// NewSupplySyncer creates a new SupplySyncer with a factory function for
// creating UniverseClient instances and a store for persisting leaves.
func NewSupplySyncer(cfg SupplySyncerConfig) SupplySyncer {
	return SupplySyncer{
		cfg: cfg,
	}
}

// retryConfig returns the backoff for universe dial, fetch, and insert.
// MaxRetries counts retries after the initial attempt. A negative value
// is clamped to zero so that attempt still runs.
func (s *SupplySyncer) retryConfig() fn.RetryConfig {
	cfg := fn.DefaultRetryConfig()
	if s.cfg.Retry != nil {
		cfg = *s.cfg.Retry
	}

	if cfg.MaxRetries < 0 {
		cfg.MaxRetries = 0
	}

	return cfg
}

// terminalSyncErr reports errors that must not be retried. A missing
// commitment is a definitive answer. A missing predecessor is repaired
// by inserting earlier commitments, not by repeating the same insert.
// Cancellation stops the sequence immediately.
func terminalSyncErr(ctx context.Context, err error) bool {
	if ctx.Err() != nil {
		return true
	}

	return errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, ErrCommitmentNotFound) ||
		errors.Is(err, ErrPrevCommitmentNotFound)
}

// retrySupplyOp calls op until it succeeds, the context is cancelled, a
// definitive supply-commit error is returned, or the retry budget is
// spent. The wait between attempts is capped and select-bound to ctx.
// Success is never returned without op having run.
func (s *SupplySyncer) retrySupplyOp(ctx context.Context,
	op func() error) error {

	cfg := s.retryConfig()
	backoff := cfg.InitialBackoff

	var (
		err       error
		attempted bool
	)
	for attempt := 0; attempt <= cfg.MaxRetries; attempt++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		attempted = true
		err = op()
		if err == nil {
			return nil
		}

		if ctx.Err() != nil {
			return ctx.Err()
		}

		if terminalSyncErr(ctx, err) || attempt == cfg.MaxRetries {
			return err
		}

		if cfg.MaxBackoff > 0 && backoff > cfg.MaxBackoff {
			backoff = cfg.MaxBackoff
		}

		log.Debugf("Supply sync attempt %d failed; retrying in %s: "+
			"%v", attempt+1, backoff, err)

		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()

			return ctx.Err()

		case <-timer.C:
		}

		next := time.Duration(float64(backoff) * cfg.BackoffMultiplier)
		if cfg.BackoffMultiplier <= 0 {
			next = backoff
		}
		if cfg.MaxBackoff > 0 && next > cfg.MaxBackoff {
			next = cfg.MaxBackoff
		}
		backoff = next
	}

	// The loop returns on every attempt. Reaching here means the
	// budget admitted no call. That is a failed sync, not a delivery.
	if !attempted {
		return errNoSupplySyncAttempt
	}

	return err
}

// insertOnce dials the server and inserts one supply commitment. A
// missing-predecessor error is returned as soon as it is observed so
// the caller can repair the chain. The dial and the insert share one
// retry budget: a fresh client is opened on every attempt.
func (s *SupplySyncer) insertOnce(ctx context.Context,
	serverAddr universe.ServerAddr, assetSpec asset.Specifier,
	commitment supplycommit.RootCommitment,
	leaves supplycommit.SupplyLeaves,
	chainProof supplycommit.ChainProof) error {

	return s.retrySupplyOp(ctx, func() error {
		client, err := s.cfg.ClientFactory(serverAddr)
		if err != nil {
			return fmt.Errorf("unable to create universe "+
				"client: %w", err)
		}

		defer func() {
			if closeErr := client.Close(); closeErr != nil {
				log.Errorf("unable to close universe "+
					"client: %v", closeErr)
			}
		}()

		err = client.InsertSupplyCommit(
			ctx, assetSpec, commitment, leaves, chainProof,
		)
		if err != nil {
			return fmt.Errorf("unable to insert supply "+
				"leaves: %w", err)
		}

		return nil
	})
}

// ancestorPush is one predecessor loaded from local history.
type ancestorPush struct {
	commitment supplycommit.RootCommitment
	leaves     supplycommit.SupplyLeaves
	chainProof supplycommit.ChainProof
}

// loadAncestors walks the spent-commitment links of commitment back to
// the first commitment that spends nothing. The returned slice is
// oldest first and does not include commitment itself.
func (s *SupplySyncer) loadAncestors(ctx context.Context,
	assetSpec asset.Specifier, commitment supplycommit.RootCommitment) (
	[]ancestorPush, error) {

	if s.cfg.History == nil {
		return nil, fmt.Errorf("unable to load missing supply "+
			"commitments: no local history: %w",
			ErrPrevCommitmentNotFound)
	}

	var newestFirst []ancestorPush
	seen := make(map[wire.OutPoint]struct{})
	current := commitment

	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		if current.SpentCommitment.IsNone() {
			break
		}

		spent, err := current.SpentCommitment.UnwrapOrErr(
			fmt.Errorf("supply commitment %s was rejected for "+
				"a missing predecessor but does not spend "+
				"one", current.CommitPoint()),
		)
		if err != nil {
			return nil, err
		}

		if _, dup := seen[spent]; dup {
			return nil, fmt.Errorf("supply commitment "+
				"predecessor cycle at %s", spent)
		}
		seen[spent] = struct{}{}

		if len(seen) > maxAncestorChain {
			return nil, fmt.Errorf("%w: more than %d predecessors",
				errSupplyChainRemainder, maxAncestorChain)
		}

		priorCommit, priorLeaves, priorProof, err :=
			s.cfg.History.FetchSupplyCommitPush(
				ctx, assetSpec, spent,
			)
		if err != nil {
			return nil, fmt.Errorf("unable to load missing "+
				"supply commitment %s: %w", spent, err)
		}

		if priorCommit.CommitPoint() != spent {
			return nil, fmt.Errorf("local supply commitment "+
				"for %s has outpoint %s", spent,
				priorCommit.CommitPoint())
		}

		newestFirst = append(newestFirst, ancestorPush{
			commitment: priorCommit,
			leaves:     priorLeaves,
			chainProof: priorProof,
		})
		current = priorCommit
	}

	for i, j := 0, len(newestFirst)-1; i < j; i, j = i+1, j-1 {
		newestFirst[i], newestFirst[j] = newestFirst[j], newestFirst[i]
	}

	return newestFirst, nil
}

// insertMissingAncestors inserts the predecessors of commitment, oldest
// first, so a server that has not seen the spent outpoint can accept
// the original commitment afterwards.
func (s *SupplySyncer) insertMissingAncestors(ctx context.Context,
	serverAddr universe.ServerAddr, assetSpec asset.Specifier,
	commitment supplycommit.RootCommitment) error {

	ancestors, err := s.loadAncestors(ctx, assetSpec, commitment)
	if err != nil {
		return err
	}

	for idx := range ancestors {
		ancestor := ancestors[idx]
		log.Infof("Universe server %s is missing supply commitment "+
			"%s; inserting it before %s", serverAddr.HostStr(),
			ancestor.commitment.CommitPoint(),
			commitment.CommitPoint())

		err = s.insertOnce(
			ctx, serverAddr, assetSpec, ancestor.commitment,
			ancestor.leaves, ancestor.chainProof,
		)
		if err != nil {
			return fmt.Errorf("unable to insert missing supply "+
				"commitment %s: %w",
				ancestor.commitment.CommitPoint(), err)
		}
	}

	return nil
}

// pushUniServer pushes the supply commitment to a specific universe
// server. A rejection for a missing predecessor inserts the earlier
// commitments this node has, oldest first, and then retries the insert.
func (s *SupplySyncer) pushUniServer(ctx context.Context,
	assetSpec asset.Specifier, commitment supplycommit.RootCommitment,
	updateLeaves supplycommit.SupplyLeaves,
	chainProof supplycommit.ChainProof,
	serverAddr universe.ServerAddr) error {

	log.Debugf("Pushing supply commitment to server: %s, asset: %s",
		serverAddr.HostStr(), assetSpec.String())

	err := s.insertOnce(
		ctx, serverAddr, assetSpec, commitment, updateLeaves,
		chainProof,
	)
	if errors.Is(err, ErrPrevCommitmentNotFound) {
		repairErr := s.insertMissingAncestors(
			ctx, serverAddr, assetSpec, commitment,
		)
		if repairErr != nil {
			return repairErr
		}

		err = s.insertOnce(
			ctx, serverAddr, assetSpec, commitment, updateLeaves,
			chainProof,
		)
	}

	if err != nil {
		return err
	}

	// Log the successful insertion to the remote universe.
	err = s.cfg.Store.LogSupplyCommitPush(
		ctx, serverAddr, assetSpec, commitment, updateLeaves,
	)
	if err != nil {
		return fmt.Errorf("unable to log supply commit push: %w", err)
	}

	log.Infof("Successfully pushed supply commitment to server: %s, "+
		"asset: %s, commitment_outpoint=%s",
		serverAddr.HostStr(), assetSpec.String(),
		commitment.CommitPoint().String())

	return nil
}

// fetchServerAddrs retrieves the list of universe server addresses that
// the syncer uses to interact with remote servers.
func (s *SupplySyncer) fetchServerAddrs(ctx context.Context,
	canonicalUniverses []url.URL) ([]universe.ServerAddr, error) {

	var zero []universe.ServerAddr

	// Fetch latest set of universe federation server addresses.
	fedAddrs, err := s.cfg.UniverseFederationView.UniverseServers(ctx)
	if err != nil {
		return zero, fmt.Errorf("unable to fetch universe servers: %w",
			err)
	}

	// Formulate final unique list of universe server addresses to push to.
	uniqueAddrs := make(map[string]universe.ServerAddr)
	for idx := range canonicalUniverses {
		addrUrl := canonicalUniverses[idx]
		serverAddr := universe.NewServerAddrFromStr(addrUrl.String())
		uniqueAddrs[serverAddr.HostStr()] = serverAddr
	}

	for idx := range fedAddrs {
		serverAddr := fedAddrs[idx]
		uniqueAddrs[serverAddr.HostStr()] = serverAddr
	}

	targetAddrs := make([]universe.ServerAddr, 0, len(uniqueAddrs))
	for _, serverAddr := range uniqueAddrs {
		targetAddrs = append(targetAddrs, serverAddr)
	}

	return targetAddrs, nil
}

// PushSupplyCommitment pushes a supply commitment to the remote universe
// server. This function should block until the sync insertion is complete.
//
// Returns a map of per-server errors keyed by server host string and
// an internal error. If all pushes succeed, both return values are nil.
// If some pushes fail, the map contains only the failed servers and
// their corresponding errors. If there's an internal/system error that
// prevents the operation from proceeding, it's returned as the second
// value.
//
// NOTE: This function must be thread safe.
func (s *SupplySyncer) PushSupplyCommitment(ctx context.Context,
	assetSpec asset.Specifier, commitment supplycommit.RootCommitment,
	updateLeaves supplycommit.SupplyLeaves,
	chainProof supplycommit.ChainProof,
	canonicalUniverses []url.URL) (map[string]error, error) {

	targetAddrs, err := s.fetchServerAddrs(ctx, canonicalUniverses)
	if err != nil {
		// This is an internal error that prevents the operation from
		// proceeding.
		return nil, fmt.Errorf("unable to fetch target universe "+
			"server addresses: %w", err)
	}

	// Skip servers that already hold this commitment. The push log
	// records every successful remote insert, and the caller retries
	// the whole dispatch whenever any one server fails — so without
	// the skip, a retry re-pushes to servers that already integrated
	// the commitment, and one persistently failing server keeps
	// every healthy one in the target set forever.
	pushed, err := s.cfg.Store.FetchPushedServers(
		ctx, assetSpec, commitment,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch pushed servers: %w",
			err)
	}
	if len(pushed) > 0 {
		pushedSet := make(map[string]struct{}, len(pushed))
		for _, host := range pushed {
			pushedSet[host] = struct{}{}
		}

		remaining := make(
			[]universe.ServerAddr, 0, len(targetAddrs),
		)
		for _, addr := range targetAddrs {
			if _, ok := pushedSet[addr.HostStr()]; ok {
				continue
			}
			remaining = append(remaining, addr)
		}

		log.Infof("Skipping %d server(s) already holding supply "+
			"commitment for asset %s",
			len(targetAddrs)-len(remaining), assetSpec.String())
		targetAddrs = remaining
	}

	log.Infof("Starting push of supply commitment for asset: %s to "+
		"%d servers", assetSpec.String(), len(targetAddrs))

	// Push the supply commitment to all target universe servers in
	// parallel. Any error for a specific server will be captured in the
	// pushErrs map and will not abort the entire operation.
	pushErrs, err := fn.ParSliceErrCollect(
		ctx, targetAddrs, func(ctx context.Context,
			serverAddr universe.ServerAddr) error {

			// Push the supply commitment to the universe server.
			err := s.pushUniServer(
				ctx, assetSpec, commitment, updateLeaves,
				chainProof, serverAddr,
			)
			if err != nil {
				return fmt.Errorf("unable to push supply "+
					"commitment (server_addr_id=%d, "+
					"server_addr_host_str=%s): %w",
					serverAddr.ID, serverAddr.HostStr(),
					err)
			}

			return nil
		},
	)
	if err != nil {
		// This should not happen with ParSliceErrCollect, but handle it
		// as an internal error.
		return nil, fmt.Errorf("unable to push supply commitment: %w",
			err)
	}

	// Build a map of errors encountered while pushing to each server.
	// If there were no errors, return nil for both values.
	if len(pushErrs) == 0 {
		return nil, nil
	}

	errorMap := make(map[string]error)
	for idx, pushErr := range pushErrs {
		serverAddr := targetAddrs[idx]
		hostStr := serverAddr.HostStr()
		errorMap[hostStr] = pushErr
	}

	return errorMap, nil
}

// pullUniServer fetches the supply commitment from a specific universe server.
func (s *SupplySyncer) pullUniServer(ctx context.Context,
	assetSpec asset.Specifier, spentCommitOutpoint fn.Option[wire.OutPoint],
	serverAddr universe.ServerAddr) (supplycommit.FetchSupplyCommitResult,
	error) {

	var zero supplycommit.FetchSupplyCommitResult

	log.Debugf("Pulling supply commitment from server: %s, asset: %s, "+
		"spent_outpoint=%v", serverAddr.HostStr(), assetSpec.String(),
		spentCommitOutpoint.IsSome())

	var result supplycommit.FetchSupplyCommitResult
	err := s.retrySupplyOp(ctx, func() error {
		client, err := s.cfg.ClientFactory(serverAddr)
		if err != nil {
			return fmt.Errorf("unable to create universe "+
				"client: %w", err)
		}

		defer func() {
			if closeErr := client.Close(); closeErr != nil {
				log.Errorf("Unable to close supply syncer "+
					"pull universe client: %v", closeErr)
			}
		}()

		fetched, err := client.FetchSupplyCommit(
			ctx, assetSpec, spentCommitOutpoint,
		)
		if err != nil {
			return fmt.Errorf("unable to fetch supply "+
				"commitment: %w", err)
		}

		result = fetched

		return nil
	})
	if err != nil {
		return zero, err
	}

	log.Infof("Successfully pulled supply commitment from server: %s, "+
		"asset: %s", serverAddr.HostStr(), assetSpec.String())

	return result, nil
}

// SupplyCommitPullResult represents the result of a supply commitment pull
// operation across multiple universe servers.
type SupplyCommitPullResult struct {
	// FetchResult contains the complete fetched supply commitment data.
	FetchResult fn.Option[supplycommit.FetchSupplyCommitResult]

	// ErrorMap contains errors encountered while pulling from each server,
	// keyed by server host string. If empty, all pulls succeeded.
	ErrorMap map[string]error
}

// PullSupplyCommitment fetches a supply commitment from remote universe
// servers. This function attempts to fetch from all servers in parallel.
//
// Returns a SupplyCommitPullResult containing the fetched data and a map of
// per-server errors, plus an internal error. If at least one server succeeds,
// the result will contain the commitment data. If all servers fail, the
// ErrorMap will contain all the errors and the commitment data will be nil.
//
// NOTE: This function must be thread safe.
func (s *SupplySyncer) PullSupplyCommitment(ctx context.Context,
	assetSpec asset.Specifier, spentCommitOutpoint fn.Option[wire.OutPoint],
	canonicalUniverses []url.URL) (SupplyCommitPullResult, error) {

	var zero SupplyCommitPullResult

	log.Infof("Starting pull of supply commitment for asset: %s, "+
		"spent_outpoint=%v, canonical_universes=%d",
		assetSpec.String(), spentCommitOutpoint.IsSome(),
		len(canonicalUniverses))

	targetAddrs, err := s.fetchServerAddrs(ctx, canonicalUniverses)
	if err != nil {
		// This is an internal error that prevents the operation from
		// proceeding.
		return zero, fmt.Errorf("unable to fetch target universe "+
			"server addresses: %w", err)
	}

	// Pull the supply commitment from all target universe servers in
	// parallel. Store both errors and successful results.
	var muResults sync.Mutex
	results := make(map[string]supplycommit.FetchSupplyCommitResult)

	// Specify context timeout for the entire pull operation.
	ctxPull, cancel := context.WithTimeout(ctx, defaultPullTimeout)
	defer cancel()

	pullErrs, err := fn.ParSliceErrCollect(
		ctxPull, targetAddrs, func(ctx context.Context,
			serverAddr universe.ServerAddr) error {

			// Pull the supply commitment from the universe server.
			result, err := s.pullUniServer(
				ctx, assetSpec, spentCommitOutpoint, serverAddr,
			)
			if err != nil {
				return fmt.Errorf("unable to pull supply "+
					"commitment (server_addr_id=%d, "+
					"server_addr_host_str=%s): %w",
					serverAddr.ID, serverAddr.HostStr(),
					err)
			}

			muResults.Lock()
			results[serverAddr.HostStr()] = result
			muResults.Unlock()

			return nil
		},
	)
	if err != nil {
		// This should not happen with ParSliceErrCollect, but handle it
		// as an internal error.
		return zero, fmt.Errorf("unable to pull supply commitment: %w",
			err)
	}

	// Report results: log server address and supply tree root.
	//
	// If the supply commitment that was pulled fails verification later,
	// we can use this log to trace back to the server it came from.
	for serverAddr, res := range results {
		// Format the spent outpoint if present, otherwise empty string.
		spentOutpointStr := fn.MapOptionZ(
			spentCommitOutpoint, func(op wire.OutPoint) string {
				return op.String()
			},
		)

		log.Infof("Pulled supply commitment from server "+
			"(server_addr=%s, asset=%s, supply_tree_root=%s, "+
			"spent_outpoint=%s)", serverAddr, assetSpec.String(),
			res.RootCommitment.SupplyRoot.NodeHash().String(),
			spentOutpointStr)
	}

	// Return one successful result, if available, as the final outcome.
	var finalResult *supplycommit.FetchSupplyCommitResult
	for _, res := range results {
		finalResult = &res
		break
	}

	// Build a map from server addresses to their corresponding errors.
	errorMap := make(map[string]error)
	for idx, pullErr := range pullErrs {
		serverAddr := targetAddrs[idx]
		hostStr := serverAddr.HostStr()
		if pullErr != nil {
			errorMap[hostStr] = pullErr
		}
	}

	return SupplyCommitPullResult{
		FetchResult: fn.MaybeSome(finalResult),
		ErrorMap:    errorMap,
	}, nil
}

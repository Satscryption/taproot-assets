package tapfreighter

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightninglabs/taproot-assets/tapsend"
	"github.com/stretchr/testify/require"
)

type mockCoinReleaser struct {
	ctx         context.Context
	ctxErr      error
	hasDeadline bool
	deadline    time.Time
	outpoints   []wire.OutPoint
}

func (m *mockCoinReleaser) ReleaseCoins(ctx context.Context,
	ops ...wire.OutPoint) error {

	m.ctx = ctx
	m.ctxErr = ctx.Err()
	m.deadline, m.hasDeadline = ctx.Deadline()
	m.outpoints = ops

	return ctx.Err()
}

// TestReleaseCoinsDetached makes sure coins are released even if the caller
// context is already canceled (taproot-assets#2206) and that the release is
// bounded.
func TestReleaseCoinsDetached(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	ops := []wire.OutPoint{{Index: 1}, {Index: 2}}
	m := &mockCoinReleaser{}
	start := time.Now()
	releaseCoinsDetached(ctx, m, ops)

	require.NoError(t, m.ctxErr)
	require.Equal(t, ops, m.outpoints)
	require.True(t, m.hasDeadline)
	require.LessOrEqual(
		t, m.deadline.Sub(start), coinReleaseTimeout+time.Second,
	)
}

// TestReleaseCoinsDetachedKeepsValues makes sure context values of the caller
// context are preserved on the release context.
func TestReleaseCoinsDetachedKeepsValues(t *testing.T) {
	t.Parallel()

	type key struct{}
	parent := context.WithValue(context.Background(), key{}, "v")

	m := &mockCoinReleaser{}
	releaseCoinsDetached(parent, m, nil)
	require.Equal(t, "v", m.ctx.Value(key{}))
}

// recordingSelector fails the orphan sweep after selection so FundPacket and
// FundBurn return on the deferred release path. Release state is snapshotted
// inside ReleaseCoins: the helper cancels its timeout context before
// returning, so the context is done by the time the caller looks at it.
type recordingSelector struct {
	selected     []*AnchoredCommitment
	releaseErr   error
	releaseValue any
	hasDeadline  bool
	deadline     time.Time
	released     []wire.OutPoint
	releaseHits  int
}

func (s *recordingSelector) SelectCoins(_ context.Context,
	_ CommitmentConstraints, _ MultiCommitmentSelectStrategy,
	_ commitment.TapCommitmentVersion) ([]*AnchoredCommitment, error) {

	return s.selected, nil
}

func (s *recordingSelector) SelectOrphanCoins(context.Context) (
	[]*ZeroValueInput, error) {

	return nil, errors.New("orphan sweep failed")
}

func (s *recordingSelector) ReleaseCoins(ctx context.Context,
	ops ...wire.OutPoint) error {

	s.releaseHits++
	s.releaseErr = ctx.Err()
	s.deadline, s.hasDeadline = ctx.Deadline()
	s.releaseValue = ctx.Value(releaseValueKey{})
	s.released = append([]wire.OutPoint(nil), ops...)

	return ctx.Err()
}

// releaseValueKey is the context key used to check that a canceled caller
// context still contributes its values to the release context.
type releaseValueKey struct{}

// TestFundErrorPathReleasesOnCanceledContext makes sure FundPacket and
// FundBurn still release selected coins when the caller context is already
// canceled. The release context keeps the caller's values and is bounded.
func TestFundErrorPathReleasesOnCanceledContext(t *testing.T) {
	t.Parallel()

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	ctx := context.WithValue(canceled, releaseValueKey{}, "lease")

	op := wire.OutPoint{Index: 4}
	run := func(t *testing.T,
		call func(*AssetWallet, context.Context) error) {

		t.Helper()

		sel := &recordingSelector{
			selected: []*AnchoredCommitment{{
				AnchorPoint: op,
			}},
		}
		wallet := NewAssetWallet(&WalletConfig{
			CoinSelector: sel,
			ChainParams:  testParams,
		})

		start := time.Now()
		err := call(wallet, ctx)
		require.ErrorContains(t, err, "orphan sweep failed")

		// One release, on a live bounded context. The old defer passed
		// the canceled caller context through and the release failed.
		require.Equal(t, 1, sel.releaseHits)
		require.NoError(t, sel.releaseErr)
		require.Equal(t, []wire.OutPoint{op}, sel.released)
		require.Equal(t, "lease", sel.releaseValue)
		require.True(t, sel.hasDeadline)
		require.LessOrEqual(
			t, sel.deadline.Sub(start),
			coinReleaseTimeout+time.Second,
		)
	}

	t.Run("fund packet", func(t *testing.T) {
		run(t, func(w *AssetWallet, ctx context.Context) error {
			_, err := w.FundPacket(
				ctx, &tapsend.FundingDescriptor{},
				&tappsbt.VPacket{ChainParams: testParams},
			)
			return err
		})
	})

	t.Run("fund burn", func(t *testing.T) {
		run(t, func(w *AssetWallet, ctx context.Context) error {
			_, err := w.FundBurn(
				ctx, &tapsend.FundingDescriptor{},
			)
			return err
		})
	})
}

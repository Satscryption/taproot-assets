package rpcserver

import (
	"errors"
	"fmt"
	"testing"

	"github.com/lightninglabs/taproot-assets/universe/supplyverifier"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestSupplyCommitStatusMapping pins the RPC boundary the syncer uses
// to recognize a missing predecessor and a missing commitment. The
// status code is the signal. A message that only looks like the
// sentinel, under a different code, must not be rewritten into it.
func TestSupplyCommitStatusMapping(t *testing.T) {
	t.Parallel()

	prev := fmt.Errorf("supply commitment verification failed: %w",
		supplyverifier.ErrPrevCommitmentNotFound)
	got := insertSupplyCommitStatus(prev)
	require.Equal(t, codes.FailedPrecondition, status.Code(got))

	mapped := mapSupplyInsertErr(got)
	require.ErrorIs(t, mapped, supplyverifier.ErrPrevCommitmentNotFound)

	lookalike := status.Error(codes.Unknown,
		"previous supply commitment not found")
	mapped = mapSupplyInsertErr(lookalike)
	require.NotErrorIs(
		t, mapped, supplyverifier.ErrPrevCommitmentNotFound,
	)

	other := insertSupplyCommitStatus(errors.New("boom"))
	require.Equal(t, codes.Unknown, status.Code(other))
	require.NotErrorIs(
		t, mapSupplyInsertErr(other),
		supplyverifier.ErrPrevCommitmentNotFound,
	)

	missing := fmt.Errorf("unable to fetch commitment: %w",
		supplyverifier.ErrCommitmentNotFound)
	got = fetchSupplyCommitStatus(missing)
	require.Equal(t, codes.NotFound, status.Code(got))
	require.ErrorIs(
		t, mapSupplyFetchErr(got), supplyverifier.ErrCommitmentNotFound,
	)

	// NotFound is not the missing-predecessor signal, even when the
	// text names that sentinel.
	notPrev := status.Error(codes.NotFound,
		"previous supply commitment not found")
	require.NotErrorIs(
		t, mapSupplyInsertErr(notPrev),
		supplyverifier.ErrPrevCommitmentNotFound,
	)
	require.ErrorIs(
		t, mapSupplyFetchErr(notPrev),
		supplyverifier.ErrCommitmentNotFound,
	)
}

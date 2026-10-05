package tapdb

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestCommitVirtualPsbtStoreRoundTrip tests insert, duplicate-key
// rejection, update, and delete of an idempotency record.
func TestCommitVirtualPsbtStoreRoundTrip(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewCommitVirtualPsbtStoreFromDB(NewTestDB(t))
	requestID := []byte("request-id")
	first := []byte("pending")

	_, err := store.FetchCommitRecord(ctx, requestID)
	require.ErrorIs(t, err, ErrNoCommitRecord)

	require.NoError(t, store.InsertCommitRecord(ctx, requestID, first))

	err = store.InsertCommitRecord(ctx, requestID, []byte("other"))
	var unique *ErrSqlUniqueConstraintViolation
	require.ErrorAs(t, err, &unique)

	got, err := store.FetchCommitRecord(ctx, requestID)
	require.NoError(t, err)
	require.Equal(t, first, got)

	listed, err := store.ListCommitRecords(ctx)
	require.NoError(t, err)
	require.Len(t, listed, 1)
	require.Equal(t, requestID, listed[0].RequestID)
	require.Equal(t, first, listed[0].Record)

	updated := []byte("completed")
	require.NoError(t, store.UpdateCommitRecord(
		ctx, requestID, updated,
	))

	got, err = store.FetchCommitRecord(ctx, requestID)
	require.NoError(t, err)
	require.Equal(t, updated, got)

	require.NoError(t, store.DeleteCommitRecord(ctx, requestID))

	_, err = store.FetchCommitRecord(ctx, requestID)
	require.ErrorIs(t, err, ErrNoCommitRecord)

	// Deleting a missing row is a no-op, so a failed attempt can be
	// abandoned more than once.
	require.NoError(t, store.DeleteCommitRecord(ctx, requestID))

	err = store.UpdateCommitRecord(ctx, requestID, []byte("gone"))
	require.ErrorIs(t, err, ErrNoCommitRecord)
}

// TestCommitVirtualPsbtStoreCompareAndSwap tests that a swap or
// conditional delete changes the row only when the stored bytes still
// match.
func TestCommitVirtualPsbtStoreCompareAndSwap(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewCommitVirtualPsbtStoreFromDB(NewTestDB(t))
	requestID := []byte("swap-id")
	first := []byte("first")

	require.NoError(t, store.InsertCommitRecord(ctx, requestID, first))

	err := store.SwapCommitRecord(
		ctx, requestID, []byte("other"), []byte("nope"), nil,
	)
	require.ErrorIs(t, err, ErrCommitRecordChanged)

	got, err := store.FetchCommitRecord(ctx, requestID)
	require.NoError(t, err)
	require.Equal(t, first, got)

	next := []byte("second")
	require.NoError(t, store.SwapCommitRecord(
		ctx, requestID, first, next, nil,
	))

	got, err = store.FetchCommitRecord(ctx, requestID)
	require.NoError(t, err)
	require.Equal(t, next, got)

	err = store.DeleteCommitRecordIf(ctx, requestID, first)
	require.ErrorIs(t, err, ErrCommitRecordChanged)

	require.NoError(t, store.DeleteCommitRecordIf(ctx, requestID, next))

	_, err = store.FetchCommitRecord(ctx, requestID)
	require.ErrorIs(t, err, ErrNoCommitRecord)

	err = store.DeleteCommitRecordIf(ctx, requestID, next)
	require.ErrorIs(t, err, ErrNoCommitRecord)
}

// TestCommitVirtualPsbtStorePurgesFinished tests that completed and
// failed rows older than the cutoff are deleted and that pending rows
// are kept even when their blob is updated.
func TestCommitVirtualPsbtStorePurgesFinished(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewCommitVirtualPsbtStoreFromDB(NewTestDB(t))

	pendingID := []byte("pending-id")
	pending := []byte("pending")
	require.NoError(t, store.InsertCommitRecord(ctx, pendingID, pending))
	require.NoError(t, store.SwapCommitRecord(
		ctx, pendingID, pending, []byte("pending-2"), nil,
	))

	oldAt := time.Now().Add(-48 * time.Hour).UTC()
	require.NoError(t, store.InsertCommitRecord(
		ctx, []byte("old-ok"), []byte("claim"),
	))
	require.NoError(t, store.SwapCommitRecord(
		ctx, []byte("old-ok"), []byte("claim"),
		[]byte("old-completed"), &oldAt,
	))

	failedAt := time.Now().Add(-48 * time.Hour).UTC()
	require.NoError(t, store.InsertCommitRecord(
		ctx, []byte("failed"), []byte("claim"),
	))
	require.NoError(t, store.SwapCommitRecord(
		ctx, []byte("failed"), []byte("claim"),
		[]byte("failed-outcome"), &failedAt,
	))

	recentAt := time.Now().UTC()
	require.NoError(t, store.InsertCommitRecord(
		ctx, []byte("new-ok"), []byte("claim"),
	))
	require.NoError(t, store.SwapCommitRecord(
		ctx, []byte("new-ok"), []byte("claim"),
		[]byte("new-completed"), &recentAt,
	))

	cutoff := time.Now().Add(-24 * time.Hour).UTC()
	deleted, err := store.PurgeFinishedCommitRecords(ctx, cutoff)
	require.NoError(t, err)
	require.EqualValues(t, 2, deleted)

	_, err = store.FetchCommitRecord(ctx, []byte("old-ok"))
	require.ErrorIs(t, err, ErrNoCommitRecord)
	_, err = store.FetchCommitRecord(ctx, []byte("failed"))
	require.ErrorIs(t, err, ErrNoCommitRecord)

	got, err := store.FetchCommitRecord(ctx, []byte("new-ok"))
	require.NoError(t, err)
	require.Equal(t, []byte("new-completed"), got)

	got, err = store.FetchCommitRecord(ctx, pendingID)
	require.NoError(t, err)
	require.Equal(t, []byte("pending-2"), got)

	unstamped, err := store.ListUnstampedCommitRecords(ctx)
	require.NoError(t, err)
	require.Len(t, unstamped, 1)
	require.Equal(t, pendingID, unstamped[0].RequestID)
}

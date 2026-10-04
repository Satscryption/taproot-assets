package tapdb

import (
	"context"
	"testing"

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

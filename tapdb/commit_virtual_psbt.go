package tapdb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
)

// ErrNoCommitRecord is returned when no CommitVirtualPsbts idempotency
// record exists for the requested key.
var ErrNoCommitRecord = errors.New("commit idempotency record not found")

// ErrCommitRecordChanged is returned when a compare-and-swap does not
// find the expected record bytes. The caller must re-read the row.
var ErrCommitRecordChanged = errors.New(
	"commit idempotency record changed",
)

// CommitVirtualPsbtQueries is the subset of sqlc methods that manage the
// commit_virtual_psbt_idem table.
type CommitVirtualPsbtQueries interface {
	InsertCommitVirtualPsbt(ctx context.Context,
		arg sqlc.InsertCommitVirtualPsbtParams) error

	FetchCommitVirtualPsbt(ctx context.Context,
		requestID []byte) ([]byte, error)

	UpdateCommitVirtualPsbt(ctx context.Context,
		arg sqlc.UpdateCommitVirtualPsbtParams) (int64, error)

	DeleteCommitVirtualPsbt(ctx context.Context, requestID []byte) error

	SwapCommitVirtualPsbt(ctx context.Context,
		arg sqlc.SwapCommitVirtualPsbtParams) (int64, error)

	DeleteCommitVirtualPsbtIf(ctx context.Context,
		arg sqlc.DeleteCommitVirtualPsbtIfParams) (int64, error)
}

// BatchedCommitVirtualPsbtStore is the transactional surface for commit
// idempotency records.
type BatchedCommitVirtualPsbtStore interface {
	CommitVirtualPsbtQueries
	BatchedTx[CommitVirtualPsbtQueries]
}

// CommitVirtualPsbtStore persists opaque CommitVirtualPsbts idempotency
// records keyed by the caller-supplied request ID. The RPC server owns the
// encoding of the blob.
type CommitVirtualPsbtStore struct {
	db BatchedCommitVirtualPsbtStore
}

// NewCommitVirtualPsbtStore returns a store backed by the given queries.
func NewCommitVirtualPsbtStore(
	db BatchedCommitVirtualPsbtStore) *CommitVirtualPsbtStore {

	return &CommitVirtualPsbtStore{db: db}
}

// NewCommitVirtualPsbtStoreFromDB builds a store on the daemon database.
func NewCommitVirtualPsbtStoreFromDB(
	db DatabaseBackend) *CommitVirtualPsbtStore {

	exec := NewTransactionExecutor(
		db, func(tx *sql.Tx) CommitVirtualPsbtQueries {
			return db.WithTx(tx)
		},
	)

	return NewCommitVirtualPsbtStore(exec)
}

// InsertCommitRecord inserts a record for a new request ID. A duplicate
// key returns *ErrSqlUniqueConstraintViolation.
func (s *CommitVirtualPsbtStore) InsertCommitRecord(ctx context.Context,
	requestID, record []byte) error {

	err := s.db.ExecTx(
		ctx, WriteTxOption(), func(q CommitVirtualPsbtQueries) error {
			err := q.InsertCommitVirtualPsbt(
				ctx, sqlc.InsertCommitVirtualPsbtParams{
					RequestID: requestID,
					Record:    record,
				},
			)
			if err != nil {
				return MapSQLError(err)
			}

			return nil
		},
	)
	if err != nil {
		return MapSQLError(err)
	}

	return nil
}

// FetchCommitRecord returns the stored record, or ErrNoCommitRecord when
// the key is absent.
func (s *CommitVirtualPsbtStore) FetchCommitRecord(ctx context.Context,
	requestID []byte) ([]byte, error) {

	var record []byte
	err := s.db.ExecTx(
		ctx, ReadTxOption(), func(q CommitVirtualPsbtQueries) error {
			out, err := q.FetchCommitVirtualPsbt(ctx, requestID)
			switch {
			case errors.Is(err, sql.ErrNoRows):
				return ErrNoCommitRecord

			case err != nil:
				return fmt.Errorf("fetch commit record: %w",
					err)
			}

			record = out

			return nil
		},
	)
	if err != nil {
		return nil, err
	}

	return record, nil
}

// UpdateCommitRecord replaces the record for an existing key.
// ErrNoCommitRecord is returned when the key is absent.
func (s *CommitVirtualPsbtStore) UpdateCommitRecord(ctx context.Context,
	requestID, record []byte) error {

	var rows int64
	err := s.db.ExecTx(
		ctx, WriteTxOption(), func(q CommitVirtualPsbtQueries) error {
			affected, err := q.UpdateCommitVirtualPsbt(
				ctx, sqlc.UpdateCommitVirtualPsbtParams{
					RequestID: requestID,
					Record:    record,
				},
			)
			if err != nil {
				return fmt.Errorf("update commit record: %w",
					err)
			}

			rows = affected

			return nil
		},
	)
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrNoCommitRecord
	}

	return nil
}

// DeleteCommitRecord removes the record for the key. Deleting a missing
// key is a no-op.
func (s *CommitVirtualPsbtStore) DeleteCommitRecord(ctx context.Context,
	requestID []byte) error {

	return s.db.ExecTx(
		ctx, WriteTxOption(), func(q CommitVirtualPsbtQueries) error {
			return q.DeleteCommitVirtualPsbt(ctx, requestID)
		},
	)
}

// SwapCommitRecord replaces the stored record when it still equals
// expected. ErrCommitRecordChanged is returned when it does not, and
// ErrNoCommitRecord when the key is absent.
func (s *CommitVirtualPsbtStore) SwapCommitRecord(ctx context.Context,
	requestID, expected, next []byte) error {

	return s.db.ExecTx(
		ctx, WriteTxOption(), func(q CommitVirtualPsbtQueries) error {
			n, err := q.SwapCommitVirtualPsbt(
				ctx, sqlc.SwapCommitVirtualPsbtParams{
					NextRecord:     next,
					RequestID:      requestID,
					ExpectedRecord: expected,
				},
			)
			if err != nil {
				return fmt.Errorf("swap commit record: %w",
					err)
			}
			if n == 1 {
				return nil
			}

			return commitRecordMiss(ctx, q, requestID)
		},
	)
}

// DeleteCommitRecordIf removes the row when it still equals expected.
// ErrCommitRecordChanged is returned when it does not, and
// ErrNoCommitRecord when the key is absent.
func (s *CommitVirtualPsbtStore) DeleteCommitRecordIf(ctx context.Context,
	requestID, expected []byte) error {

	return s.db.ExecTx(
		ctx, WriteTxOption(), func(q CommitVirtualPsbtQueries) error {
			n, err := q.DeleteCommitVirtualPsbtIf(
				ctx, sqlc.DeleteCommitVirtualPsbtIfParams{
					RequestID:      requestID,
					ExpectedRecord: expected,
				},
			)
			if err != nil {
				return fmt.Errorf("delete commit record: %w",
					err)
			}
			if n == 1 {
				return nil
			}

			return commitRecordMiss(ctx, q, requestID)
		},
	)
}

// commitRecordMiss explains a compare-and-swap that matched no row.
func commitRecordMiss(ctx context.Context, q CommitVirtualPsbtQueries,
	requestID []byte) error {

	_, err := q.FetchCommitVirtualPsbt(ctx, requestID)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return ErrNoCommitRecord

	case err != nil:
		return fmt.Errorf("fetch commit record: %w", err)

	default:
		return ErrCommitRecordChanged
	}
}

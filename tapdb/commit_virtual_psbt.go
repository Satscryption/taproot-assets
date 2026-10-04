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

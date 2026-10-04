package rpcserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/tapconfig"
	"github.com/lightninglabs/taproot-assets/tapdb"
	"github.com/lightninglabs/taproot-assets/taprpc"
	wrpc "github.com/lightninglabs/taproot-assets/taprpc/assetwalletrpc"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const (
	// maxCommitRequestIDLen is the longest accepted request_id. It
	// matches the primary key check on commit_virtual_psbt_idem.
	maxCommitRequestIDLen = 64

	// commitIdempotencyIOTimeout bounds store writes that must not
	// follow the request context. A cancelled client still needs the
	// outcome recorded or the claim released.
	commitIdempotencyIOTimeout = 30 * time.Second

	commitRecordVersion byte = 1

	commitStatusPending   uint8 = 1
	commitStatusCompleted uint8 = 2

	maxCommitLockIDLen   = 256
	maxCommitOutpoints   = 4096
	maxCommitResponseLen = 32 << 20
)

// commitVirtualPsbtsHooks let the idempotency wrapper observe funding
// without owning the commit pipeline. Both fields are optional.
type commitVirtualPsbtsHooks struct {
	// onFunded is called after lnd returns leases and before later
	// errors can drop those outpoints. A non-nil error aborts the
	// commit and releases the leases.
	onFunded func(lockID []byte, utxos []*taprpc.OutPoint) error

	// onResult is called with the finished response before lease
	// cleanup is cancelled. A non-nil error aborts the commit and
	// releases the leases.
	onResult func(*wrpc.CommitVirtualPsbtsResponse) error
}

// commitOnceFunc performs one CommitVirtualPsbts attempt.
type commitOnceFunc func(context.Context, *wrpc.CommitVirtualPsbtsRequest,
	*commitVirtualPsbtsHooks) (*wrpc.CommitVirtualPsbtsResponse, error)

// commitRecord is the persisted outcome of one request ID.
type commitRecord struct {
	Status      uint8
	RequestHash [32]byte
	LockID      []byte
	Outpoints   []*taprpc.OutPoint
	Response    []byte
}

// CommitVirtualPsbts creates the output commitments and proofs for the given
// virtual transactions by committing them to the BTC level anchor transaction.
// In addition, the BTC level anchor transaction is funded and prepared up to
// the point where it is ready to be signed.
//
// When the request sets a request ID, a repeat of the same request returns
// the stored response and does not fund again. GetCommitVirtualPsbtsStatus
// reports an in-progress or completed call and the lnd leases it holds.
func (r *RPCServer) CommitVirtualPsbts(ctx context.Context,
	req *wrpc.CommitVirtualPsbtsRequest) (*wrpc.CommitVirtualPsbtsResponse,
	error) {

	return r.commitVirtualPsbts(ctx, req, r.fundAndCommitVirtualPsbts)
}

// commitVirtualPsbts is CommitVirtualPsbts with the single-attempt work
// injected so tests can observe funding without a live lnd.
func (r *RPCServer) commitVirtualPsbts(ctx context.Context,
	req *wrpc.CommitVirtualPsbtsRequest, once commitOnceFunc) (
	*wrpc.CommitVirtualPsbtsResponse, error) {

	if len(req.RequestId) == 0 {
		return once(ctx, req, nil)
	}

	if err := validateCommitRequestID(req.RequestId); err != nil {
		return nil, err
	}

	if _, err := r.commitStore(); err != nil {
		return nil, err
	}

	// Derive a stable lock ID before hashing so a retry that also
	// leaves custom_lock_id empty matches this request.
	ensureCommitLockID(req)

	hash, err := hashCommitRequest(req)
	if err != nil {
		return nil, err
	}

	var (
		claimed  bool
		finished bool
	)
	defer func() {
		if claimed && !finished {
			r.abandonCommitRecord(req.RequestId)
		}
	}()

	replay, claimed, err := r.claimCommit(ctx, req, hash)
	if err != nil {
		return nil, err
	}
	if !claimed {
		return replay, nil
	}

	// A cancelled caller must not fund. The defer releases the claim.
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	resp, err := once(ctx, req, r.commitHooks(req.RequestId))
	if err != nil {
		return nil, err
	}

	finished = true

	return resp, nil
}

// GetCommitVirtualPsbtsStatus reports the recorded outcome of a
// CommitVirtualPsbts call. An unknown request ID is a successful response
// with status unknown.
func (r *RPCServer) GetCommitVirtualPsbtsStatus(ctx context.Context,
	req *wrpc.GetCommitVirtualPsbtsStatusRequest) (
	*wrpc.GetCommitVirtualPsbtsStatusResponse, error) {

	if req == nil {
		return nil, status.Error(
			codes.InvalidArgument, "request is required",
		)
	}

	if err := validateCommitRequestID(req.RequestId); err != nil {
		return nil, err
	}

	store, err := r.commitStore()
	if err != nil {
		return nil, err
	}

	raw, err := store.FetchCommitRecord(ctx, req.RequestId)
	switch {
	case errors.Is(err, tapdb.ErrNoCommitRecord):
		return &wrpc.GetCommitVirtualPsbtsStatusResponse{
			Status: commitStatusUnknown,
		}, nil

	case err != nil:
		return nil, fmt.Errorf("fetch commit record: %w", err)
	}

	rec, err := decodeCommitRecord(raw)
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "stored commit record is invalid: %v",
			err,
		)
	}

	st, err := commitProtoStatus(rec.Status)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &wrpc.GetCommitVirtualPsbtsStatusResponse{
		Status:         st,
		LockId:         rec.LockID,
		LndLockedUtxos: rec.Outpoints,
	}, nil
}

// Proto status values. The generated names do not fit in 80 columns.
var (
	commitStatusUnknown = wrpc.CommitVirtualPsbtsStatus_COMMIT_VIRTUAL_PSBTS_STATUS_UNKNOWN //nolint:lll

	commitStatusPendingProto = wrpc.CommitVirtualPsbtsStatus_COMMIT_VIRTUAL_PSBTS_STATUS_PENDING //nolint:lll

	commitStatusCompletedProto = wrpc.CommitVirtualPsbtsStatus_COMMIT_VIRTUAL_PSBTS_STATUS_COMPLETED //nolint:lll
)

func commitProtoStatus(recordStatus uint8) (wrpc.CommitVirtualPsbtsStatus,
	error) {

	switch recordStatus {
	case commitStatusPending:
		return commitStatusPendingProto, nil

	case commitStatusCompleted:
		return commitStatusCompletedProto, nil

	default:
		return 0, fmt.Errorf(
			"unknown commit record status %d", recordStatus,
		)
	}
}

func (r *RPCServer) commitHooks(requestID []byte) *commitVirtualPsbtsHooks {
	return &commitVirtualPsbtsHooks{
		onFunded: func(lockID []byte, utxos []*taprpc.OutPoint) error {
			return r.updateCommitRecord(
				requestID, func(rec *commitRecord) error {
					if len(lockID) > 0 {
						rec.LockID = lockID
					}
					rec.Outpoints = utxos

					return nil
				},
			)
		},
		onResult: func(resp *wrpc.CommitVirtualPsbtsResponse) error {
			raw, err := proto.Marshal(resp)
			if err != nil {
				return fmt.Errorf(
					"marshal commit response: %w", err,
				)
			}

			return r.updateCommitRecord(
				requestID, func(rec *commitRecord) error {
					rec.Status = commitStatusCompleted
					rec.Response = raw
					rec.Outpoints = resp.GetLndLockedUtxos()

					return nil
				},
			)
		},
	}
}

func (r *RPCServer) claimCommit(ctx context.Context,
	req *wrpc.CommitVirtualPsbtsRequest, hash [32]byte) (
	*wrpc.CommitVirtualPsbtsResponse, bool, error) {

	store := r.cfg.CommitIdempotency

	raw, err := store.FetchCommitRecord(ctx, req.RequestId)
	switch {
	case err == nil:
		resp, err := replayCommit(raw, hash)

		return resp, false, err

	case errors.Is(err, tapdb.ErrNoCommitRecord):
		// The key is free. Claim it below.

	default:
		return nil, false, fmt.Errorf(
			"fetch commit record: %w", err,
		)
	}

	rec := &commitRecord{
		Status:      commitStatusPending,
		RequestHash: hash,
		LockID:      append([]byte(nil), req.CustomLockId...),
	}
	encoded, err := encodeCommitRecord(rec)
	if err != nil {
		return nil, false, err
	}

	err = store.InsertCommitRecord(ctx, req.RequestId, encoded)
	if err == nil {
		return nil, true, nil
	}

	var unique *tapdb.ErrSqlUniqueConstraintViolation
	if !errors.As(err, &unique) {
		return nil, false, fmt.Errorf(
			"insert commit record: %w", err,
		)
	}

	raw, err = store.FetchCommitRecord(ctx, req.RequestId)
	if err != nil {
		return nil, false, fmt.Errorf("fetch commit record: %w", err)
	}

	resp, err := replayCommit(raw, hash)

	return resp, false, err
}

func replayCommit(raw []byte, hash [32]byte) (
	*wrpc.CommitVirtualPsbtsResponse, error) {

	rec, err := decodeCommitRecord(raw)
	if err != nil {
		return nil, status.Errorf(
			codes.Internal, "stored commit record is invalid: %v",
			err,
		)
	}

	if rec.RequestHash != hash {
		return nil, status.Error(
			codes.InvalidArgument,
			"request_id was already used with a different request",
		)
	}

	switch rec.Status {
	case commitStatusCompleted:
		if len(rec.Response) == 0 {
			return nil, status.Error(
				codes.Internal,
				"stored commit response is empty",
			)
		}

		resp := &wrpc.CommitVirtualPsbtsResponse{}
		err := proto.Unmarshal(rec.Response, resp)
		if err != nil {
			return nil, status.Errorf(
				codes.Internal,
				"stored commit response is invalid: %v", err,
			)
		}

		return resp, nil

	case commitStatusPending:
		return nil, status.Error(
			codes.Aborted,
			"commit for this request_id is in progress or has "+
				"no recorded outcome; query "+
				"GetCommitVirtualPsbtsStatus",
		)

	default:
		return nil, status.Errorf(
			codes.Internal, "unknown commit record status %d",
			rec.Status,
		)
	}
}

func (r *RPCServer) updateCommitRecord(requestID []byte,
	mutate func(*commitRecord) error) error {

	ctx, cancel := commitRecordContext()
	defer cancel()

	raw, err := r.cfg.CommitIdempotency.FetchCommitRecord(ctx, requestID)
	if err != nil {
		return fmt.Errorf("fetch commit record: %w", err)
	}

	rec, err := decodeCommitRecord(raw)
	if err != nil {
		return err
	}

	if err := mutate(rec); err != nil {
		return err
	}

	encoded, err := encodeCommitRecord(rec)
	if err != nil {
		return err
	}

	err = r.cfg.CommitIdempotency.UpdateCommitRecord(
		ctx, requestID, encoded,
	)
	if err != nil {
		return fmt.Errorf("update commit record: %w", err)
	}

	return nil
}

func (r *RPCServer) abandonCommitRecord(requestID []byte) {
	ctx, cancel := commitRecordContext()
	defer cancel()

	err := r.cfg.CommitIdempotency.DeleteCommitRecord(ctx, requestID)
	if err != nil {
		rpcsLog.Errorf("Error abandoning commit request %x: %v",
			requestID, err)
	}
}

func (r *RPCServer) commitStore() (tapconfig.CommitIdempotencyStore, error) {
	if r.cfg == nil || r.cfg.CommitIdempotency == nil {
		return nil, status.Error(
			codes.Internal,
			"commit idempotency store is not configured",
		)
	}

	return r.cfg.CommitIdempotency, nil
}

func commitRecordContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(
		context.Background(), commitIdempotencyIOTimeout,
	)
}

func validateCommitRequestID(id []byte) error {
	if len(id) == 0 {
		return status.Error(
			codes.InvalidArgument, "request_id is empty",
		)
	}
	if len(id) > maxCommitRequestIDLen {
		return status.Errorf(
			codes.InvalidArgument,
			"request_id must be at most %d bytes",
			maxCommitRequestIDLen,
		)
	}

	return nil
}

// ensureCommitLockID sets a stable lnd lock ID when the caller asked for
// idempotency but did not choose one. The ID is SHA-256(request_id).
func ensureCommitLockID(req *wrpc.CommitVirtualPsbtsRequest) {
	if len(req.RequestId) == 0 || len(req.CustomLockId) > 0 {
		return
	}

	sum := sha256.Sum256(req.RequestId)
	req.CustomLockId = append([]byte(nil), sum[:]...)
}

func hashCommitRequest(req *wrpc.CommitVirtualPsbtsRequest) ([32]byte, error) {
	raw, err := proto.Marshal(req)
	if err != nil {
		return [32]byte{}, fmt.Errorf("marshal commit request: %w", err)
	}

	return sha256.Sum256(raw), nil
}

func effectiveCommitLockID(leases []*walletrpc.UtxoLease,
	fallback []byte) []byte {

	for _, lease := range leases {
		if lease == nil || len(lease.Id) == 0 {
			continue
		}

		return append([]byte(nil), lease.Id...)
	}

	return append([]byte(nil), fallback...)
}

func outpointsFromWire(ops []wire.OutPoint) []*taprpc.OutPoint {
	out := make([]*taprpc.OutPoint, len(ops))
	for i := range ops {
		out[i] = &taprpc.OutPoint{
			Txid:        append([]byte(nil), ops[i].Hash[:]...),
			OutputIndex: ops[i].Index,
		}
	}

	return out
}

func encodeCommitRecord(rec *commitRecord) ([]byte, error) {
	if rec == nil {
		return nil, fmt.Errorf("nil commit record")
	}
	if len(rec.LockID) > maxCommitLockIDLen {
		return nil, fmt.Errorf(
			"lock id longer than %d bytes", maxCommitLockIDLen,
		)
	}
	if len(rec.Outpoints) > maxCommitOutpoints {
		return nil, fmt.Errorf("too many locked outpoints")
	}
	if len(rec.Response) > maxCommitResponseLen {
		return nil, fmt.Errorf(
			"commit response longer than %d bytes",
			maxCommitResponseLen,
		)
	}

	for _, op := range rec.Outpoints {
		if op == nil || len(op.Txid) != chainhash.HashSize {
			return nil, fmt.Errorf(
				"locked outpoint txid must be %d bytes",
				chainhash.HashSize,
			)
		}
	}

	var buf bytes.Buffer
	buf.WriteByte(commitRecordVersion)
	buf.WriteByte(rec.Status)
	buf.Write(rec.RequestHash[:])

	if err := binary.Write(
		&buf, binary.BigEndian, uint16(len(rec.LockID)),
	); err != nil {
		return nil, err
	}
	buf.Write(rec.LockID)

	if err := binary.Write(
		&buf, binary.BigEndian, uint16(len(rec.Outpoints)),
	); err != nil {
		return nil, err
	}
	for _, op := range rec.Outpoints {
		buf.Write(op.Txid)
		if err := binary.Write(
			&buf, binary.BigEndian, op.OutputIndex,
		); err != nil {
			return nil, err
		}
	}

	if err := binary.Write(
		&buf, binary.BigEndian, uint32(len(rec.Response)),
	); err != nil {
		return nil, err
	}
	buf.Write(rec.Response)

	return buf.Bytes(), nil
}

func decodeCommitRecord(raw []byte) (*commitRecord, error) {
	r := bytes.NewReader(raw)

	version, err := r.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("read commit record version: %w", err)
	}
	if version != commitRecordVersion {
		return nil, fmt.Errorf(
			"unsupported commit record version %d", version,
		)
	}

	recStatus, err := r.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("read commit record status: %w", err)
	}

	var hash [32]byte
	if _, err := io.ReadFull(r, hash[:]); err != nil {
		return nil, fmt.Errorf("read commit request hash: %w", err)
	}

	var lockLen uint16
	if err := binary.Read(r, binary.BigEndian, &lockLen); err != nil {
		return nil, fmt.Errorf("read lock id length: %w", err)
	}
	if int(lockLen) > maxCommitLockIDLen {
		return nil, fmt.Errorf(
			"lock id longer than %d bytes", maxCommitLockIDLen,
		)
	}

	lockID := make([]byte, lockLen)
	if _, err := io.ReadFull(r, lockID); err != nil {
		return nil, fmt.Errorf("read lock id: %w", err)
	}

	var numOutpoints uint16
	if err := binary.Read(
		r, binary.BigEndian, &numOutpoints,
	); err != nil {
		return nil, fmt.Errorf("read outpoint count: %w", err)
	}
	if int(numOutpoints) > maxCommitOutpoints {
		return nil, fmt.Errorf("too many locked outpoints")
	}

	outpoints := make([]*taprpc.OutPoint, numOutpoints)
	for i := range outpoints {
		txid := make([]byte, chainhash.HashSize)
		if _, err := io.ReadFull(r, txid); err != nil {
			return nil, fmt.Errorf("read outpoint txid: %w", err)
		}

		var index uint32
		if err := binary.Read(
			r, binary.BigEndian, &index,
		); err != nil {
			return nil, fmt.Errorf("read outpoint index: %w", err)
		}

		outpoints[i] = &taprpc.OutPoint{
			Txid:        txid,
			OutputIndex: index,
		}
	}

	var respLen uint32
	if err := binary.Read(r, binary.BigEndian, &respLen); err != nil {
		return nil, fmt.Errorf("read response length: %w", err)
	}
	if respLen > maxCommitResponseLen {
		return nil, fmt.Errorf(
			"commit response longer than %d bytes",
			maxCommitResponseLen,
		)
	}

	var response []byte
	if respLen > 0 {
		response = make([]byte, respLen)
		if _, err := io.ReadFull(r, response); err != nil {
			return nil, fmt.Errorf("read commit response: %w", err)
		}
	}

	return &commitRecord{
		Status:      recStatus,
		RequestHash: hash,
		LockID:      lockID,
		Outpoints:   outpoints,
		Response:    response,
	}, nil
}

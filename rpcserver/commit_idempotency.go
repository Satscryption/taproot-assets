package rpcserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/tapconfig"
	"github.com/lightninglabs/taproot-assets/tapdb"
	"github.com/lightninglabs/taproot-assets/taprpc"
	wrpc "github.com/lightninglabs/taproot-assets/taprpc/assetwalletrpc"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
	"github.com/lightningnetwork/lnd/lnwallet/chanfunding"
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

	// commitRecordVersion1 is the original record layout. It has no
	// lease timestamps. Rows already stored in that layout still
	// decode.
	commitRecordVersion1 byte = 1

	// commitRecordVersion is the layout that also stores when the
	// pending row was created and when its lnd lease expires.
	commitRecordVersion byte = 2

	commitStatusPending   uint8 = 1
	commitStatusCompleted uint8 = 2

	// lndLockIDLen is the size of an lnd wallet lock ID.
	lndLockIDLen = 32

	maxCommitLockIDLen   = 256
	maxCommitOutpoints   = 4096
	maxCommitResponseLen = 32 << 20

	// maxCommitLockSeconds is the largest lock duration that fits in
	// a time.Duration. A larger request value would overflow and look
	// like a lease that already expired.
	maxCommitLockSeconds = uint64(math.MaxInt64 / int64(time.Second))
)

var (
	// errLeasesUnavailable is returned when the daemon has no lnd
	// wallet to ask which outputs are still leased.
	errLeasesUnavailable = errors.New(
		"wallet lease query is not configured",
	)

	// errCommitAttemptReplaced is returned when a retry has taken
	// over the pending row this attempt was writing.
	errCommitAttemptReplaced = errors.New(
		"commit attempt was replaced",
	)
)

// commitVirtualPsbtsHooks let the idempotency wrapper observe funding
// without owning the commit pipeline. The callbacks are optional.
type commitVirtualPsbtsHooks struct {
	// onFunded is called after lnd returns leases and before later
	// errors can drop those outpoints. expiry is the earliest
	// absolute lease expiration, or the zero time when lnd did not
	// report one. A non-nil error aborts the commit and releases
	// the leases.
	onFunded func(lockID []byte, utxos []*taprpc.OutPoint,
		expiry time.Time) error

	// onResult is called with the finished response before lease
	// cleanup is cancelled. A non-nil error aborts the commit and
	// releases the leases.
	onResult func(*wrpc.CommitVirtualPsbtsResponse) error

	// retainPending tells the caller not to delete the pending row
	// when this attempt returns an error. It is set when releasing
	// the lnd leases failed, so a later retry can see them.
	retainPending bool

	// attemptReplaced is set when a newer attempt owns the row. The
	// leases this attempt acquired must not be released: they may
	// already belong to that newer attempt.
	attemptReplaced bool
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

	// CreatedAt is when this pending attempt claimed the key.
	CreatedAt time.Time

	// LeaseExpiry is when the lnd leases for this attempt stop being
	// held. Before funding returns it is the requested duration
	// added to CreatedAt. After funding it is the earliest
	// expiration lnd reported.
	LeaseExpiry time.Time
}

// CommitVirtualPsbts creates the output commitments and proofs for the given
// virtual transactions by committing them to the BTC level anchor transaction.
// In addition, the BTC level anchor transaction is funded and prepared up to
// the point where it is ready to be signed.
//
// When the request sets a request ID, a repeat of the same request returns
// the stored response and does not fund again. A repeat while that call
// is still running, or while lnd still leases its inputs, is rejected.
// A repeat of the same body after those leases are gone funds again.
// The same key with a different body is rejected. GetCommitVirtualPsbtsStatus
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

	replay, claimed, attempt, err := r.claimCommit(ctx, req, hash)
	if err != nil {
		return nil, err
	}
	if !claimed {
		return replay, nil
	}

	hooks := r.commitHooks(req.RequestId, attempt)
	finished := false
	defer func() {
		if finished || hooks.retainPending {
			return
		}

		r.abandonCommitRecord(req.RequestId, attempt)
	}()

	// A cancelled caller must not fund. The defer releases the claim.
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	resp, err := once(ctx, req, hooks)
	if err != nil {
		return nil, err
	}

	finished = true

	return resp, nil
}

// GetCommitVirtualPsbtsStatus reports the recorded outcome of a
// CommitVirtualPsbts call. An unknown request ID is a successful response
// with status unknown. A pending row stays pending after its leases
// expire, and the outpoints in the response are the ones recorded for
// that commit. When funding has returned but the row lists no outpoints
// and lnd still holds the lock, those leases are recorded and returned.
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

	if rec.Status == commitStatusPending && len(rec.Outpoints) == 0 {
		reconciled, err := r.backfillPendingLeases(
			ctx, req.RequestId, rec,
		)
		if err != nil {
			rpcsLog.Errorf("Error reconciling commit leases "+
				"for %x: %v", req.RequestId, err)
		} else if reconciled != nil {
			rec = reconciled
		}
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

func (r *RPCServer) commitHooks(requestID []byte,
	attempt time.Time) *commitVirtualPsbtsHooks {

	hooks := &commitVirtualPsbtsHooks{}
	hooks.onFunded = func(lockID []byte, utxos []*taprpc.OutPoint,
		expiry time.Time) error {

		err := r.updateCommitRecord(
			requestID, attempt, func(rec *commitRecord) error {
				if len(lockID) > 0 {
					rec.LockID = append(
						[]byte(nil), lockID...,
					)
				}
				rec.Outpoints = utxos
				if !expiry.IsZero() {
					rec.LeaseExpiry = expiry
				}

				return nil
			},
		)
		if errors.Is(err, errCommitAttemptReplaced) {
			hooks.attemptReplaced = true
		}

		return err
	}
	hooks.onResult = func(resp *wrpc.CommitVirtualPsbtsResponse) error {
		raw, err := proto.Marshal(resp)
		if err != nil {
			return fmt.Errorf(
				"marshal commit response: %w", err,
			)
		}

		err = r.updateCommitRecord(
			requestID, attempt, func(rec *commitRecord) error {
				rec.Status = commitStatusCompleted
				rec.Response = raw
				rec.Outpoints = resp.GetLndLockedUtxos()

				return nil
			},
		)
		if errors.Is(err, errCommitAttemptReplaced) {
			hooks.attemptReplaced = true
		}

		return err
	}

	return hooks
}

func (r *RPCServer) claimCommit(ctx context.Context,
	req *wrpc.CommitVirtualPsbtsRequest, hash [32]byte) (
	*wrpc.CommitVirtualPsbtsResponse, bool, time.Time, error) {

	// Two passes cover a compare-and-swap that loses to another
	// retry. A fresh insert that loses the unique-key race does not
	// take over that winner.
	for pass := 0; pass < 2; pass++ {
		raw, err := r.cfg.CommitIdempotency.FetchCommitRecord(
			ctx, req.RequestId,
		)
		switch {
		case errors.Is(err, tapdb.ErrNoCommitRecord):
			return r.insertPendingCommit(ctx, req, hash)

		case err != nil:
			return nil, false, time.Time{}, fmt.Errorf(
				"fetch commit record: %w", err,
			)
		}

		resp, claimed, attempt, again, err := r.claimExisting(
			ctx, req, hash, raw,
		)
		if err != nil || !again {
			return resp, claimed, attempt, err
		}
	}

	return nil, false, time.Time{}, status.Error(
		codes.Aborted,
		"commit for this request_id is in progress or has "+
			"no recorded outcome; query "+
			"GetCommitVirtualPsbtsStatus",
	)
}

// claimExisting handles a request ID that already has a row. again is
// set when the row changed under us and the caller should re-read it.
func (r *RPCServer) claimExisting(ctx context.Context,
	req *wrpc.CommitVirtualPsbtsRequest, hash [32]byte, raw []byte) (
	*wrpc.CommitVirtualPsbtsResponse, bool, time.Time, bool, error) {

	rec, err := decodeCommitRecord(raw)
	if err != nil {
		return nil, false, time.Time{}, false, status.Errorf(
			codes.Internal, "stored commit record is invalid: %v",
			err,
		)
	}

	if rec.RequestHash != hash {
		return nil, false, time.Time{}, false, status.Error(
			codes.InvalidArgument,
			"request_id was already used with a different request",
		)
	}

	switch rec.Status {
	case commitStatusCompleted:
		resp, err := completedCommitResponse(rec)

		return resp, false, time.Time{}, false, err

	case commitStatusPending:
		// Handled below.

	default:
		return nil, false, time.Time{}, false, status.Errorf(
			codes.Internal, "unknown commit record status %d",
			rec.Status,
		)
	}

	state, err := r.inspectPending(ctx, rec)
	if err != nil {
		return nil, false, time.Time{}, false, err
	}
	if !state.recoverable {
		if len(rec.Outpoints) == 0 && len(state.live) > 0 {
			if _, err := r.backfillPendingLeases(
				ctx, req.RequestId, rec,
			); err != nil {
				rpcsLog.Errorf("Error recording commit "+
					"leases for %x: %v", req.RequestId,
					err)
			}
		}

		return nil, false, time.Time{}, false, pendingCommitAborted()
	}

	err = r.cfg.CommitIdempotency.DeleteCommitRecordIf(
		ctx, req.RequestId, raw,
	)
	switch {
	case err == nil:
		resp, claimed, attempt, err := r.insertPendingCommit(
			ctx, req, hash,
		)

		return resp, claimed, attempt, false, err

	case errors.Is(err, tapdb.ErrCommitRecordChanged),
		errors.Is(err, tapdb.ErrNoCommitRecord):

		return nil, false, time.Time{}, true, nil

	default:
		return nil, false, time.Time{}, false, fmt.Errorf(
			"delete stale commit record: %w", err,
		)
	}
}

func (r *RPCServer) insertPendingCommit(ctx context.Context,
	req *wrpc.CommitVirtualPsbtsRequest, hash [32]byte) (
	*wrpc.CommitVirtualPsbtsResponse, bool, time.Time, error) {

	now := time.Now()
	rec := &commitRecord{
		Status:      commitStatusPending,
		RequestHash: hash,
		LockID:      append([]byte(nil), req.CustomLockId...),
		CreatedAt:   now,
		LeaseExpiry: now.Add(commitLockDuration(
			req.LockExpirationSeconds,
		)),
	}
	encoded, err := encodeCommitRecord(rec)
	if err != nil {
		return nil, false, time.Time{}, err
	}

	err = r.cfg.CommitIdempotency.InsertCommitRecord(
		ctx, req.RequestId, encoded,
	)
	if err == nil {
		return nil, true, now, nil
	}

	var unique *tapdb.ErrSqlUniqueConstraintViolation
	if !errors.As(err, &unique) {
		return nil, false, time.Time{}, fmt.Errorf(
			"insert commit record: %w", err,
		)
	}

	// The winner of the insert owns the key. Do not take that row
	// over; the caller is told the commit is in progress unless the
	// winner already finished.
	raw, err := r.cfg.CommitIdempotency.FetchCommitRecord(
		ctx, req.RequestId,
	)
	if err != nil {
		return nil, false, time.Time{}, fmt.Errorf(
			"fetch commit record: %w", err,
		)
	}

	resp, err := replayCommit(raw, hash)

	return resp, false, time.Time{}, err
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
		return completedCommitResponse(rec)

	case commitStatusPending:
		return nil, pendingCommitAborted()

	default:
		return nil, status.Errorf(
			codes.Internal, "unknown commit record status %d",
			rec.Status,
		)
	}
}

func completedCommitResponse(rec *commitRecord) (
	*wrpc.CommitVirtualPsbtsResponse, error) {

	if len(rec.Response) == 0 {
		return nil, status.Error(
			codes.Internal, "stored commit response is empty",
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
}

func pendingCommitAborted() error {
	return status.Error(
		codes.Aborted,
		"commit for this request_id is in progress or has "+
			"no recorded outcome; query "+
			"GetCommitVirtualPsbtsStatus",
	)
}

func (r *RPCServer) updateCommitRecord(requestID []byte, attempt time.Time,
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
	if !sameCommitAttempt(rec.CreatedAt, attempt) {
		return errCommitAttemptReplaced
	}

	if err := mutate(rec); err != nil {
		return err
	}

	encoded, err := encodeCommitRecord(rec)
	if err != nil {
		return err
	}

	err = r.cfg.CommitIdempotency.SwapCommitRecord(
		ctx, requestID, raw, encoded,
	)
	switch {
	case err == nil:
		return nil

	case errors.Is(err, tapdb.ErrCommitRecordChanged):
		return errCommitAttemptReplaced

	default:
		return fmt.Errorf("update commit record: %w", err)
	}
}

func (r *RPCServer) abandonCommitRecord(requestID []byte,
	attempt time.Time) {

	ctx, cancel := commitRecordContext()
	defer cancel()

	raw, err := r.cfg.CommitIdempotency.FetchCommitRecord(ctx, requestID)
	switch {
	case errors.Is(err, tapdb.ErrNoCommitRecord):
		return

	case err != nil:
		rpcsLog.Errorf("Error abandoning commit request %x: %v",
			requestID, err)

		return
	}

	rec, err := decodeCommitRecord(raw)
	if err != nil {
		rpcsLog.Errorf("Error abandoning commit request %x: %v",
			requestID, err)

		return
	}
	if !sameCommitAttempt(rec.CreatedAt, attempt) {
		return
	}

	held, err := r.leasesRemain(ctx, rec)
	if err != nil {
		rpcsLog.Errorf("Error checking commit leases for %x: %v",
			requestID, err)

		return
	}
	if held {
		rpcsLog.Infof("Keeping commit request %x: lnd still "+
			"leases its outputs", requestID)

		return
	}

	err = r.cfg.CommitIdempotency.DeleteCommitRecordIf(
		ctx, requestID, raw,
	)
	switch {
	case err == nil, errors.Is(err, tapdb.ErrNoCommitRecord),
		errors.Is(err, tapdb.ErrCommitRecordChanged):

		return

	default:
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

	if err := binary.Write(
		&buf, binary.BigEndian, unixNano(rec.CreatedAt),
	); err != nil {
		return nil, err
	}
	if err := binary.Write(
		&buf, binary.BigEndian, unixNano(rec.LeaseExpiry),
	); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func decodeCommitRecord(raw []byte) (*commitRecord, error) {
	r := bytes.NewReader(raw)

	version, err := r.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("read commit record version: %w", err)
	}
	if version != commitRecordVersion1 && version != commitRecordVersion {
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

	var createdAt, leaseExpiry time.Time
	if version == commitRecordVersion {
		var createdNano, expiryNano int64
		if err := binary.Read(
			r, binary.BigEndian, &createdNano,
		); err != nil {
			return nil, fmt.Errorf("read commit created time: %w",
				err)
		}
		if err := binary.Read(
			r, binary.BigEndian, &expiryNano,
		); err != nil {
			return nil, fmt.Errorf("read commit lease expiry: %w",
				err)
		}
		createdAt = timeFromUnixNano(createdNano)
		leaseExpiry = timeFromUnixNano(expiryNano)
	}

	return &commitRecord{
		Status:      recStatus,
		RequestHash: hash,
		LockID:      lockID,
		Outpoints:   outpoints,
		Response:    response,
		CreatedAt:   createdAt,
		LeaseExpiry: leaseExpiry,
	}, nil
}

// pendingLeaseState is what lnd currently holds for one pending row.
type pendingLeaseState struct {
	// recoverable is true when a retry of the same request may fund
	// again. The recorded leases are gone, and a call that has not
	// funded yet is old enough that it is no longer in flight.
	recoverable bool

	// live are leases still held under the record's lock ID.
	live []lndclient.LeaseDescriptor
}

func (r *RPCServer) inspectPending(ctx context.Context,
	rec *commitRecord) (pendingLeaseState, error) {

	leases, err := r.commitLeases(ctx)
	switch {
	case errors.Is(err, errLeasesUnavailable):
		return pendingLeaseState{}, nil

	case err != nil:
		return pendingLeaseState{}, fmt.Errorf(
			"list wallet leases: %w", err,
		)
	}

	matched := leasesForLock(rec.LockID, leases)
	if len(rec.Outpoints) > 0 {
		if outpointsStillLeased(rec, leases) {
			return pendingLeaseState{live: matched}, nil
		}

		return pendingLeaseState{recoverable: true}, nil
	}

	if len(matched) > 0 {
		return pendingLeaseState{live: matched}, nil
	}
	if rec.LeaseExpiry.IsZero() || time.Now().Before(rec.LeaseExpiry) {
		return pendingLeaseState{}, nil
	}

	return pendingLeaseState{recoverable: true}, nil
}

// leasesRemain reports whether this attempt's outputs are still leased.
// A missing wallet reports that they are not, so unit tests that do
// not configure lnd keep the previous delete-on-failure behaviour. A
// failed query after funding was recorded keeps the row.
func (r *RPCServer) leasesRemain(ctx context.Context,
	rec *commitRecord) (bool, error) {

	leases, err := r.commitLeases(ctx)
	switch {
	case errors.Is(err, errLeasesUnavailable):
		return false, nil

	case err != nil:
		if len(rec.Outpoints) > 0 {
			return true, nil
		}

		return false, nil
	}

	if len(rec.Outpoints) > 0 {
		return outpointsStillLeased(rec, leases), nil
	}

	return len(leasesForLock(rec.LockID, leases)) > 0, nil
}

func (r *RPCServer) commitLeases(ctx context.Context) (
	[]lndclient.LeaseDescriptor, error) {

	if r.cfg == nil || r.cfg.Lnd == nil || r.cfg.Lnd.WalletKit == nil {
		return nil, errLeasesUnavailable
	}

	return r.cfg.Lnd.WalletKit.ListLeases(ctx)
}

// backfillPendingLeases stores outpoints discovered from lnd when
// funding returned but the pending row does not list them yet.
func (r *RPCServer) backfillPendingLeases(ctx context.Context,
	requestID []byte, rec *commitRecord) (*commitRecord, error) {

	if rec == nil || len(rec.Outpoints) > 0 {
		return rec, nil
	}

	state, err := r.inspectPending(ctx, rec)
	if err != nil || len(state.live) == 0 {
		return rec, err
	}

	err = r.updateCommitRecord(
		requestID, rec.CreatedAt, func(cur *commitRecord) error {
			if len(cur.Outpoints) > 0 {
				return nil
			}

			cur.Outpoints = outpointsFromLeases(state.live)
			cur.LockID = append(
				[]byte(nil), state.live[0].LockID[:]...,
			)
			if exp := earliestDescriptorExpiry(
				state.live,
			); !exp.IsZero() {
				cur.LeaseExpiry = exp
			}

			return nil
		},
	)
	if err != nil && !errors.Is(err, errCommitAttemptReplaced) {
		return nil, err
	}

	raw, err := r.cfg.CommitIdempotency.FetchCommitRecord(ctx, requestID)
	if err != nil {
		return nil, fmt.Errorf("fetch commit record: %w", err)
	}

	return decodeCommitRecord(raw)
}

func leasesForLock(lockID []byte,
	leases []lndclient.LeaseDescriptor) []lndclient.LeaseDescriptor {

	if len(lockID) != lndLockIDLen {
		return nil
	}

	matched := make([]lndclient.LeaseDescriptor, 0, len(leases))
	for _, lease := range leases {
		if bytes.Equal(lockID, lease.LockID[:]) {
			matched = append(matched, lease)
		}
	}

	return matched
}

func outpointsStillLeased(rec *commitRecord,
	leases []lndclient.LeaseDescriptor) bool {

	matched := leasesForLock(rec.LockID, leases)
	for _, op := range rec.Outpoints {
		if op == nil {
			continue
		}
		for _, lease := range matched {
			if lease.Outpoint.Index == op.OutputIndex &&
				bytes.Equal(lease.Outpoint.Hash[:], op.Txid) {

				return true
			}
		}
	}

	return false
}

func outpointsFromLeases(
	leases []lndclient.LeaseDescriptor) []*taprpc.OutPoint {

	out := make([]*taprpc.OutPoint, 0, len(leases))
	for _, lease := range leases {
		out = append(out, &taprpc.OutPoint{
			Txid: append(
				[]byte(nil), lease.Outpoint.Hash[:]...,
			),
			OutputIndex: lease.Outpoint.Index,
		})
	}

	return out
}

func earliestDescriptorExpiry(
	leases []lndclient.LeaseDescriptor) time.Time {

	var earliest time.Time
	for _, lease := range leases {
		if lease.Expiration.IsZero() {
			continue
		}
		if earliest.IsZero() || lease.Expiration.Before(earliest) {
			earliest = lease.Expiration
		}
	}

	return earliest
}

func earliestUtxoLeaseExpiry(leases []*walletrpc.UtxoLease) time.Time {
	var earliest time.Time
	for _, lease := range leases {
		if lease == nil || lease.Expiration == 0 {
			continue
		}

		exp := time.Unix(int64(lease.Expiration), 0)
		if earliest.IsZero() || exp.Before(earliest) {
			earliest = exp
		}
	}

	return earliest
}

func commitLockDuration(seconds uint64) time.Duration {
	if seconds == 0 {
		return chanfunding.DefaultLockDuration
	}
	if seconds > maxCommitLockSeconds {
		seconds = maxCommitLockSeconds
	}

	return time.Duration(seconds) * time.Second
}

func sameCommitAttempt(stored, attempt time.Time) bool {
	return stored.Equal(attempt)
}

func unixNano(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}

	return t.UnixNano()
}

func timeFromUnixNano(n int64) time.Time {
	if n == 0 {
		return time.Time{}
	}

	return time.Unix(0, n)
}

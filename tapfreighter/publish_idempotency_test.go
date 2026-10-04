package tapfreighter

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightninglabs/taproot-assets/tapsend"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/stretchr/testify/require"
)

// queryParcelLog is an ExportLog that serves parcels by anchor txid.
type queryParcelLog struct {
	ExportLog

	mu      sync.Mutex
	parcels []*OutboundParcel
	err     error
	calls   atomic.Int32

	// block, when set, is waited on inside QueryParcels.
	block chan struct{}
}

func (q *queryParcelLog) QueryParcels(_ context.Context,
	anchorTxHash *chainhash.Hash, _ bool) ([]*OutboundParcel, error) {

	q.calls.Add(1)
	if q.block != nil {
		<-q.block
	}
	if q.err != nil {
		return nil, q.err
	}
	if anchorTxHash == nil {
		return nil, nil
	}

	q.mu.Lock()
	defer q.mu.Unlock()

	var matched []*OutboundParcel
	for _, parcel := range q.parcels {
		if parcel.AnchorTx == nil {
			continue
		}
		if parcel.AnchorTx.TxHash() == *anchorTxHash {
			matched = append(matched, parcel)
		}
	}

	return matched, nil
}

func testAnchorTx(value int64) *wire.MsgTx {
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(&wire.OutPoint{}, nil, nil))
	tx.AddTxOut(wire.NewTxOut(value, []byte{0x51}))

	return tx
}

func testPreAnchoredParcel(tx *wire.MsgTx) *PreAnchoredParcel {
	return NewPreAnchoredParcel(
		[]*tappsbt.VPacket{{
			Outputs: []*tappsbt.VOutput{{}},
		}},
		nil,
		&tapsend.AnchorTransaction{
			FundedPsbt: &tapsend.FundedPsbt{
				Pkt: &psbt.Packet{},
			},
			FinalTx: tx,
		},
		true, "pubandlog", fn.None[uint32](),
	)
}

func testPorter(log ExportLog) *ChainPorter {
	return NewChainPorter(&ChainPorterConfig{
		ExportLog: log,
	})
}

// shipmentResult is the outcome of one RequestShipment call.
type shipmentResult struct {
	resp *OutboundParcel
	err  error
}

// requestShipmentAsync runs RequestShipment and fails the test if it does
// not return before the timeout. A lost-response retry must not block in
// the state machine once the anchor is already logged.
func requestShipmentAsync(t *testing.T, porter *ChainPorter,
	parcel Parcel) shipmentResult {

	t.Helper()

	result := make(chan shipmentResult, 1)
	go func() {
		resp, err := porter.RequestShipment(parcel)
		result <- shipmentResult{resp: resp, err: err}
	}()

	select {
	case got := <-result:
		return got

	case <-time.After(2 * time.Second):
		t.Fatal("shipment did not return")
		return shipmentResult{}
	}
}

// TestPreAnchoredShipmentReturnsLoggedTransfer asserts that a repeat
// publish of an anchor that is already logged returns that transfer and
// does not enqueue another shipment.
func TestPreAnchoredShipmentReturnsLoggedTransfer(t *testing.T) {
	t.Parallel()

	tx := testAnchorTx(1_000)
	logged := &OutboundParcel{
		AnchorTx: tx,
		Label:    "existing",
	}
	log := &queryParcelLog{
		parcels: []*OutboundParcel{logged},
	}
	porter := testPorter(log)
	t.Cleanup(func() {
		close(porter.Quit)
	})

	parcel := testPreAnchoredParcel(tx)
	parcel.SetRequestID([]byte("req-1"))

	got := requestShipmentAsync(t, porter, parcel)
	require.NoError(t, got.err)
	require.Same(t, logged, got.resp)

	// A second call, with a different request ID, still returns the
	// logged transfer. The new ID is then bound to this anchor.
	other := testPreAnchoredParcel(tx)
	other.SetRequestID([]byte("req-2"))
	got = requestShipmentAsync(t, porter, other)
	require.NoError(t, got.err)
	require.Same(t, logged, got.resp)

	// An empty request ID reconciles the same way.
	plain := testPreAnchoredParcel(tx)
	got = requestShipmentAsync(t, porter, plain)
	require.NoError(t, got.err)
	require.Same(t, logged, got.resp)

	select {
	case extra := <-porter.outboundParcels:
		t.Fatalf("logged anchor was shipped again: %v", extra)

	default:
	}
}

// TestPreAnchoredShipmentDoesNotSucceedAfterDoubleSpend asserts that a
// transfer row written before broadcast is not a successful publish when
// that broadcast failed with ErrDoubleSpend. A retry must surface the
// failure. The same anchor with no request ID, the shape channel
// funding uses, is not a success either.
func TestPreAnchoredShipmentDoesNotSucceedAfterDoubleSpend(t *testing.T) {
	t.Parallel()

	tx := testAnchorTx(1_000)
	parcelLog := &queryParcelLog{}
	porter := testPorter(parcelLog)
	t.Cleanup(func() {
		close(porter.Quit)
	})

	parcel := testPreAnchoredParcel(tx)
	parcel.SetRequestID([]byte("req-fail"))

	done := make(chan shipmentResult, 1)
	go func() {
		resp, err := porter.RequestShipment(parcel)
		done <- shipmentResult{resp: resp, err: err}
	}()

	var got Parcel
	select {
	case got = <-porter.outboundParcels:
	case <-time.After(2 * time.Second):
		t.Fatal("anchor was not shipped")
	}

	// StorePreBroadcast has already persisted the row. Broadcast then
	// fails because the anchor can never confirm.
	got.kit().errChan <- fmt.Errorf("unable to broadcast "+
		"transaction %v: %w", tx.TxHash(), lnwallet.ErrDoubleSpend)

	select {
	case result := <-done:
		require.ErrorIs(t, result.err, lnwallet.ErrDoubleSpend)

	case <-time.After(2 * time.Second):
		t.Fatal("broadcast failure was not delivered")
	}

	parcelLog.mu.Lock()
	parcelLog.parcels = []*OutboundParcel{{
		AnchorTx: tx,
		Label:    "stranded",
	}}
	parcelLog.mu.Unlock()

	retry := testPreAnchoredParcel(tx)
	retry.SetRequestID([]byte("req-fail"))
	gotRetry := requestShipmentAsync(t, porter, retry)
	require.ErrorIs(t, gotRetry.err, lnwallet.ErrDoubleSpend)
	require.Nil(t, gotRetry.resp)

	// Channel funding and close ship a pre-anchored parcel with no
	// request ID. A failed broadcast of that anchor is the same row.
	plain := testPreAnchoredParcel(tx)
	gotPlain := requestShipmentAsync(t, porter, plain)
	require.ErrorIs(t, gotPlain.err, lnwallet.ErrDoubleSpend)
	require.Nil(t, gotPlain.resp)

	select {
	case extra := <-porter.outboundParcels:
		t.Fatalf("failed anchor was shipped again: %v", extra)

	default:
	}
}

// TestPreAnchoredShipmentRejectsReusedRequestID asserts that one request
// ID cannot publish two different anchor transactions while the first
// publish is still in flight.
func TestPreAnchoredShipmentRejectsReusedRequestID(t *testing.T) {
	t.Parallel()

	tx := testAnchorTx(1_000)
	block := make(chan struct{})
	parcelLog := &queryParcelLog{block: block}
	porter := testPorter(parcelLog)
	t.Cleanup(func() {
		close(porter.Quit)
	})

	first := testPreAnchoredParcel(tx)
	first.SetRequestID([]byte("same-id"))

	done := make(chan shipmentResult, 1)
	go func() {
		resp, err := porter.RequestShipment(first)
		done <- shipmentResult{resp: resp, err: err}
	}()

	require.Eventually(t, func() bool {
		return parcelLog.calls.Load() >= 1
	}, time.Second, 5*time.Millisecond)

	other := testPreAnchoredParcel(testAnchorTx(2_000))
	other.SetRequestID([]byte("same-id"))
	got := requestShipmentAsync(t, porter, other)
	require.ErrorIs(t, got.err, ErrPublishRequestIDReused)

	close(block)

	var shipped Parcel
	select {
	case shipped = <-porter.outboundParcels:
	case <-time.After(2 * time.Second):
		t.Fatal("in-flight anchor was not shipped")
	}

	logged := &OutboundParcel{AnchorTx: tx}
	shipped.kit().respChan <- logged

	select {
	case result := <-done:
		require.NoError(t, result.err)
		require.Equal(t, logged, result.resp)

	case <-time.After(2 * time.Second):
		t.Fatal("in-flight shipment did not finish")
	}
}

// TestPublishRequestIDsReleasedWhenPublishEnds asserts that a request
// ID is dropped once its publish completes, so distinct IDs do not
// accumulate for the life of the process.
func TestPublishRequestIDsReleasedWhenPublishEnds(t *testing.T) {
	t.Parallel()

	const n = 8
	parcels := make([]*OutboundParcel, n)
	for i := 0; i < n; i++ {
		parcels[i] = &OutboundParcel{
			AnchorTx: testAnchorTx(int64(1_000 + i)),
		}
	}
	porter := testPorter(&queryParcelLog{parcels: parcels})
	t.Cleanup(func() {
		close(porter.Quit)
	})

	for i := 0; i < n; i++ {
		parcel := testPreAnchoredParcel(parcels[i].AnchorTx)
		parcel.SetRequestID([]byte{byte(i + 1)})
		got := requestShipmentAsync(t, porter, parcel)
		require.NoError(t, got.err)
		require.Same(t, parcels[i], got.resp)
	}

	porter.publishMu.Lock()
	defer porter.publishMu.Unlock()
	require.Empty(t, porter.publishRequestIDs)
}

// TestPublishRequestIDContractIsProcessLocal asserts the published
// contract matches the binding we keep: process-local and in-flight
// only. A new porter is a restart and accepts an id the previous
// process already used.
func TestPublishRequestIDContractIsProcessLocal(t *testing.T) {
	t.Parallel()

	_, file, _, ok := runtime.Caller(0)
	require.True(t, ok)
	root := filepath.Join(filepath.Dir(file), "..")

	const phrase = "process-local and in-flight only"
	for _, rel := range []string{
		"taprpc/assetwalletrpc/assetwallet.proto",
		"docs/release-notes/release-notes-0.9.0.md",
	} {
		body, err := os.ReadFile(filepath.Join(root, rel))
		require.NoError(t, err)
		require.Contains(t, string(body), phrase, rel)
	}

	notes, err := os.ReadFile(filepath.Join(
		root, "docs/release-notes/release-notes-0.9.0.md",
	))
	require.NoError(t, err)
	require.NotContains(t, string(notes), "life of the process")

	tx := testAnchorTx(1_000)
	previous := testPorter(&queryParcelLog{
		parcels: []*OutboundParcel{{AnchorTx: tx}},
	})
	t.Cleanup(func() {
		close(previous.Quit)
	})

	parcel := testPreAnchoredParcel(tx)
	parcel.SetRequestID([]byte("restart-id"))
	got := requestShipmentAsync(t, previous, parcel)
	require.NoError(t, got.err)

	restarted := testPorter(&queryParcelLog{})
	t.Cleanup(func() {
		close(restarted.Quit)
	})

	other := testPreAnchoredParcel(testAnchorTx(2_000))
	other.SetRequestID([]byte("restart-id"))

	done := make(chan shipmentResult, 1)
	go func() {
		resp, err := restarted.RequestShipment(other)
		done <- shipmentResult{resp: resp, err: err}
	}()

	select {
	case shipped := <-restarted.outboundParcels:
		shipped.kit().respChan <- &OutboundParcel{
			AnchorTx: other.anchorTx.FinalTx,
		}

	case result := <-done:
		require.NotErrorIs(t, result.err, ErrPublishRequestIDReused)
		t.Fatalf("restarted porter rejected the publish: %v",
			result.err)

	case <-time.After(2 * time.Second):
		t.Fatal("restarted porter did not accept the request id")
	}

	select {
	case result := <-done:
		require.NoError(t, result.err)

	case <-time.After(2 * time.Second):
		t.Fatal("restarted publish did not finish")
	}
}

// TestPreAnchoredShipmentQueryErrorDoesNotEnqueue asserts that a failed
// transfer lookup is returned to the caller and does not start a
// shipment that might log a second row.
func TestPreAnchoredShipmentQueryErrorDoesNotEnqueue(t *testing.T) {
	t.Parallel()

	queryErr := errors.New("db down")
	porter := testPorter(&queryParcelLog{err: queryErr})
	t.Cleanup(func() {
		close(porter.Quit)
	})

	got := requestShipmentAsync(t, porter, testPreAnchoredParcel(
		testAnchorTx(1_000),
	))
	require.ErrorIs(t, got.err, queryErr)

	select {
	case extra := <-porter.outboundParcels:
		t.Fatalf("shipment enqueued after query error: %v", extra)

	default:
	}
}

// TestPreAnchoredShipmentEnqueuesNewAnchor asserts that an anchor with
// no logged transfer is still handed to the state machine.
func TestPreAnchoredShipmentEnqueuesNewAnchor(t *testing.T) {
	t.Parallel()

	tx := testAnchorTx(1_000)
	porter := testPorter(&queryParcelLog{})
	t.Cleanup(func() {
		close(porter.Quit)
	})

	parcel := testPreAnchoredParcel(tx)
	parcel.SetRequestID([]byte("new"))

	done := make(chan shipmentResult, 1)
	go func() {
		resp, err := porter.RequestShipment(parcel)
		done <- shipmentResult{resp: resp, err: err}
	}()

	var got Parcel
	select {
	case got = <-porter.outboundParcels:
	case <-time.After(2 * time.Second):
		t.Fatal("new anchor was not shipped")
	}

	shipped := &OutboundParcel{AnchorTx: tx, Label: "shipped"}
	got.kit().respChan <- shipped

	select {
	case result := <-done:
		require.NoError(t, result.err)
		require.Equal(t, shipped, result.resp)

	case <-time.After(2 * time.Second):
		t.Fatal("shipment result was not delivered")
	}
}

// TestPreAnchoredShipmentCoalescesInFlight asserts that two publishes of
// an anchor that is not yet logged share one state-machine run.
func TestPreAnchoredShipmentCoalescesInFlight(t *testing.T) {
	t.Parallel()

	tx := testAnchorTx(1_000)
	block := make(chan struct{})
	log := &queryParcelLog{block: block}
	porter := testPorter(log)
	t.Cleanup(func() {
		close(porter.Quit)
	})

	start := make(chan struct{})
	var ready sync.WaitGroup
	ready.Add(2)

	results := make([]shipmentResult, 2)
	var wg sync.WaitGroup
	for idx := 0; idx < 2; idx++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			ready.Done()
			<-start

			parcel := testPreAnchoredParcel(tx)
			parcel.SetRequestID([]byte{byte(i + 1)})
			resp, err := porter.RequestShipment(parcel)
			results[i] = shipmentResult{resp: resp, err: err}
		}(idx)
	}
	ready.Wait()
	close(start)

	require.Eventually(t, func() bool {
		return log.calls.Load() >= 1
	}, time.Second, 5*time.Millisecond)

	// The follower must join the in-flight publish rather than query
	// and enqueue a second one.
	time.Sleep(50 * time.Millisecond)
	require.EqualValues(t, 1, log.calls.Load())

	close(block)

	var got Parcel
	select {
	case got = <-porter.outboundParcels:
	case <-time.After(2 * time.Second):
		t.Fatal("in-flight anchor was not shipped")
	}

	select {
	case extra := <-porter.outboundParcels:
		t.Fatalf("second shipment enqueued: %v", extra)

	default:
	}

	shipped := &OutboundParcel{AnchorTx: tx, Label: "once"}
	got.kit().respChan <- shipped

	finished := make(chan struct{})
	go func() {
		wg.Wait()
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("in-flight shipments did not finish")
	}

	require.NoError(t, results[0].err)
	require.NoError(t, results[1].err)
	require.Equal(t, shipped, results[0].resp)
	require.Equal(t, shipped, results[1].resp)
}

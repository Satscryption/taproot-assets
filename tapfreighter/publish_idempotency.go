package tapfreighter

import (
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightningnetwork/lnd/lnwallet"
)

// ErrPublishRequestIDReused is returned when a publish request ID is
// presented again for a different anchor transaction than the one it was
// first bound to.
var ErrPublishRequestIDReused = errors.New("publish request id already " +
	"used for a different anchor transaction")

// preAnchoredFlight is one in-flight pre-anchored publish. Followers
// wait on done and share the leader's result.
type preAnchoredFlight struct {
	done chan struct{}
	resp *OutboundParcel
	err  error
}

func newPreAnchoredFlight() *preAnchoredFlight {
	return &preAnchoredFlight{
		done: make(chan struct{}),
	}
}

func (f *preAnchoredFlight) wait() (*OutboundParcel, error) {
	<-f.done

	return f.resp, f.err
}

func (f *preAnchoredFlight) finish(resp *OutboundParcel, err error) {
	f.resp = resp
	f.err = err
	close(f.done)
}

// requestPreAnchoredShipment reconciles a pre-anchored publish with a
// transfer already logged for its anchor, and coalesces concurrent
// publishes of that anchor onto one shipment.
func (p *ChainPorter) requestPreAnchoredShipment(
	parcel *PreAnchoredParcel) (*OutboundParcel, error) {

	txHash := parcel.anchorTx.FinalTx.TxHash()

	p.publishMu.Lock()
	if err := p.bindPublishRequestID(parcel.requestID, txHash); err != nil {
		p.publishMu.Unlock()

		return nil, err
	}
	if flight := p.preAnchoredFlights[txHash]; flight != nil {
		p.publishMu.Unlock()

		return flight.wait()
	}

	flight := newPreAnchoredFlight()
	p.preAnchoredFlights[txHash] = flight
	p.publishMu.Unlock()

	resp, err := p.shipPreAnchored(parcel)

	p.publishMu.Lock()
	// The row is durable before broadcast. Remember a double spend
	// so a retry cannot report that row as a successful publish.
	if errors.Is(err, lnwallet.ErrDoubleSpend) {
		p.terminalBroadcasts[txHash] = err
	}
	flight.finish(resp, err)
	delete(p.preAnchoredFlights, txHash)
	// Followers bind before they wait, so every ID for this anchor
	// is in the map. Drop them with the flight: the binding only has
	// to reject reuse while the publish is in flight.
	p.releasePublishRequestIDs(txHash)
	p.publishMu.Unlock()

	return resp, err
}

// bindPublishRequestID records that id belongs to txHash. The caller must
// hold publishMu. An empty id is not bound. Reuse for a different anchor
// is rejected.
func (p *ChainPorter) bindPublishRequestID(id []byte,
	txHash chainhash.Hash) error {

	if len(id) == 0 {
		return nil
	}

	key := string(id)
	prev, ok := p.publishRequestIDs[key]
	if ok && prev != txHash {
		return fmt.Errorf("%w", ErrPublishRequestIDReused)
	}

	p.publishRequestIDs[key] = txHash

	return nil
}

// releasePublishRequestIDs drops every request ID bound to txHash. The
// caller must hold publishMu. IDs for other anchors are left in place,
// including ones whose publish is still in flight.
func (p *ChainPorter) releasePublishRequestIDs(txHash chainhash.Hash) {
	for key, bound := range p.publishRequestIDs {
		if bound == txHash {
			delete(p.publishRequestIDs, key)
		}
	}
}

// terminalBroadcastFailure returns the double-spend error recorded for
// txHash, or nil. The caller must not hold publishMu.
func (p *ChainPorter) terminalBroadcastFailure(
	txHash chainhash.Hash) error {

	p.publishMu.Lock()
	defer p.publishMu.Unlock()

	return p.terminalBroadcasts[txHash]
}

// shipPreAnchored returns the transfer already logged for the parcel's
// anchor, or enqueues a new shipment when none is logged. A logged
// anchor whose broadcast failed with ErrDoubleSpend is returned as
// that failure.
func (p *ChainPorter) shipPreAnchored(
	parcel *PreAnchoredParcel) (*OutboundParcel, error) {

	ctx, cancel := p.WithCtxQuit()
	defer cancel()

	txHash := parcel.anchorTx.FinalTx.TxHash()
	existing, err := p.QueryParcels(ctx, fn.Some(txHash), false)
	if err != nil {
		return nil, fmt.Errorf("unable to query logged transfer: %w",
			err)
	}
	if len(existing) > 0 {
		// A row is written in StorePreBroadcast, before
		// PublishTransaction. ErrDoubleSpend means that anchor
		// can never confirm; the row is not a successful publish.
		bcastErr := p.terminalBroadcastFailure(txHash)
		if bcastErr != nil {
			log.Infof("Anchor transaction %v was logged but its "+
				"broadcast failed and can never confirm",
				txHash)

			return nil, bcastErr
		}

		log.Infof("Anchor transaction %v already logged; returning "+
			"the existing transfer", txHash)

		return existing[0], nil
	}

	return p.enqueueShipment(parcel)
}

// enqueueShipment hands a parcel to the porter state machine and waits
// for its initial response.
func (p *ChainPorter) enqueueShipment(req Parcel) (*OutboundParcel, error) {
	if !fn.SendOrQuit(p.outboundParcels, req, p.Quit) {
		return nil, fmt.Errorf("ChainPorter shutting down")
	}

	select {
	case err := <-req.kit().errChan:
		return nil, err

	case resp := <-req.kit().respChan:
		return resp, nil

	case <-p.Quit:
		return nil, fmt.Errorf("ChainPorter shutting down")
	}
}

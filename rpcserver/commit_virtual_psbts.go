package rpcserver

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcutil/psbt"
	wrpc "github.com/lightninglabs/taproot-assets/taprpc/assetwalletrpc"
)

// ErrAnchorChangeAdded is returned by CommitVirtualPsbts if the caller asked
// for no new anchor change output but funding would add one.
var ErrAnchorChangeAdded = errors.New("unexpected anchor change output")

// checkNoNewAnchorChange verifies that funding a BTC anchor template via lnd
// did not add a new change output, which is what a CommitVirtualPsbts caller
// asks for by setting anchor_change_output{add=false}.
//
// lnd's PsbtCoinSelect path matches on the type of the change output oneof and
// never evaluates the boolean, so add=false behaves like add=true and lnd
// appends a P2TR change output whenever the leftover exceeds the dust limit
// (https://github.com/lightninglabs/taproot-assets/issues/2209). Until lnd
// offers a real no-change mode, we fail closed instead of silently returning a
// different output topology than the one the caller requested.
//
// template is the anchor packet before funding. funded is the packet returned
// by lnd and changeIndex is the change output index lnd reported (-1 if none).
//
// Outputs are compared in index order. A pair matches only when the values
// are equal and the pk scripts are equal; nil and empty scripts compare
// equal. Any reordering, value change, or script change is a mismatch, as
// is a different output count or a reported change index.
func checkNoNewAnchorChange(template *psbt.Packet, funded *psbt.Packet,
	changeIndex int32) error {

	templateOutputs := len(template.UnsignedTx.TxOut)
	fundedOutputs := len(funded.UnsignedTx.TxOut)

	for idx := 0; idx < templateOutputs; idx++ {
		if idx >= fundedOutputs {
			break
		}

		tplOut := template.UnsignedTx.TxOut[idx]
		fndOut := funded.UnsignedTx.TxOut[idx]
		if tplOut.Value != fndOut.Value ||
			!bytes.Equal(tplOut.PkScript, fndOut.PkScript) {

			return fmt.Errorf("%w: anchor_change_output add=false "+
				"cannot be honored, lnd changed the anchor "+
				"output set (change output index %d, outputs "+
				"%d -> %d); use skip_funding=true with "+
				"caller-supplied inputs or add=true (see "+
				"lightninglabs/taproot-assets#2209)",
				ErrAnchorChangeAdded, changeIndex,
				templateOutputs, fundedOutputs)
		}
	}

	if changeIndex == -1 && fundedOutputs == templateOutputs {
		return nil
	}

	return fmt.Errorf("%w: anchor_change_output add=false cannot be "+
		"honored, lnd changed the anchor output set (change output "+
		"index %d, outputs %d -> %d); use skip_funding=true with "+
		"caller-supplied inputs or add=true (see "+
		"lightninglabs/taproot-assets#2209)", ErrAnchorChangeAdded,
		changeIndex, templateOutputs, fundedOutputs)
}

// noNewAnchorChangeRequested reports whether CommitVirtualPsbts must reject
// funding that alters the anchor output set. skip_funding does not ask lnd
// to select coins, so the caller template is left as-is and this check does
// not apply. Selecting an existing output as change is also unchanged.
func noNewAnchorChangeRequested(req *wrpc.CommitVirtualPsbtsRequest) bool {
	if req.SkipFunding {
		return false
	}

	change := req.AnchorChangeOutput
	addOpt, ok := change.(*wrpc.CommitVirtualPsbtsRequest_Add)

	return ok && !addOpt.Add
}

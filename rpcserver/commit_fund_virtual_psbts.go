package rpcserver

import (
	"bytes"
	"context"
	"fmt"

	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightninglabs/taproot-assets/tapsend"
	walletrpc "github.com/lightningnetwork/lnd/lnrpc/walletrpc"
	wrpc "github.com/lightninglabs/taproot-assets/taprpc/assetwalletrpc"
)

// fundAndCommitVirtualPsbts creates the output commitments and proofs for
// the given virtual transactions and funds the BTC level anchor. hooks may
// be nil. When set, onFunded runs after lnd returns the leased inputs and
// onResult runs with the finished response before those leases are kept.
func (r *RPCServer) fundAndCommitVirtualPsbts(ctx context.Context,
	req *wrpc.CommitVirtualPsbtsRequest,
	hooks *commitVirtualPsbtsHooks) (*wrpc.CommitVirtualPsbtsResponse,
	error) {

	if len(req.VirtualPsbts) == 0 {
		return nil, fmt.Errorf("no virtual PSBTs specified")
	}

	pkt, err := psbt.NewFromRawBytes(bytes.NewReader(req.AnchorPsbt), false)
	if err != nil {
		return nil, fmt.Errorf("error decoding packet: %w", err)
	}

	activePackets, err := decodeVirtualPackets(req.VirtualPsbts)
	if err != nil {
		return nil, fmt.Errorf("error decoding active packets: %w", err)
	}

	passivePackets, err := decodeVirtualPackets(req.PassiveAssetPsbts)
	if err != nil {
		return nil, fmt.Errorf("error decoding passive packets: %w",
			err)
	}

	// Make sure the assets given fully satisfy the input commitments.
	allPackets := append([]*tappsbt.VPacket{}, activePackets...)
	allPackets = append(allPackets, passivePackets...)
	err = r.validateInputAssets(ctx, pkt, allPackets)
	if err != nil {
		return nil, fmt.Errorf("error validating input assets: %w", err)
	}

	proofOpts, err := transitionProofOptions(req.TransitionProofVersion)
	if err != nil {
		return nil, err
	}

	// We're ready to attempt to fund the transaction now. For that we first
	// need to re-serialize our packet.
	packetBytes, err := fn.Serialize(pkt)
	if err != nil {
		return nil, fmt.Errorf("error serializing packet: %w", err)
	}

	var (
		lockedUTXO      []*walletrpc.UtxoLease
		lockedOutpoints []wire.OutPoint
		fundedPacket    *psbt.Packet = pkt
		changeIndex     int32        = -1
		success         bool
	)

	if !req.SkipFunding {
		unlockInputs := lockCommitInputs(req.CustomLockId)
		defer unlockInputs()

		// The change output and fee parameters of this RPC are
		// identical to the walletrpc.FundPsbt, so we just map them 1:1
		// and let lnd do the validation.
		coinSelect := &walletrpc.PsbtCoinSelect{
			Psbt: packetBytes,
		}
		fundRequest := &walletrpc.FundPsbtRequest{
			Template: &walletrpc.FundPsbtRequest_CoinSelect{
				CoinSelect: coinSelect,
			},
			MinConfs:              1,
			ChangeType:            P2TRChangeType,
			CustomLockId:          req.CustomLockId,
			LockExpirationSeconds: req.LockExpirationSeconds,
		}

		// Unfortunately we can't use the same RPC types, so we have to
		// do a 1:1 mapping to the walletrpc types for the anchor change
		// output and fee "oneof" fields.
		switch change := req.AnchorChangeOutput.(type) {
		case *wrpc.CommitVirtualPsbtsRequest_ExistingOutputIndex:
			coinSelect.ChangeOutput = &coinSelectExistingIndex{
				ExistingOutputIndex: change.ExistingOutputIndex,
			}

		case *wrpc.CommitVirtualPsbtsRequest_Add:
			coinSelect.ChangeOutput = &walletrpc.PsbtCoinSelect_Add{
				Add: change.Add,
			}

		default:
			return nil, fmt.Errorf("unknown change output type")
		}

		switch fee := req.Fees.(type) {
		case *wrpc.CommitVirtualPsbtsRequest_TargetConf:
			fundRequest.Fees =
				&walletrpc.FundPsbtRequest_TargetConf{
					TargetConf: fee.TargetConf,
				}

		case *wrpc.CommitVirtualPsbtsRequest_SatPerVbyte:
			fundRequest.Fees =
				&walletrpc.FundPsbtRequest_SatPerVbyte{
					SatPerVbyte: fee.SatPerVbyte,
				}

		default:
			return nil, fmt.Errorf("unknown fee type")
		}

		lndWallet := r.cfg.Lnd.WalletKit
		fundedPacket, changeIndex, lockedUTXO, err = lndWallet.FundPsbt(
			ctx, fundRequest,
		)
		if err != nil {
			return nil, fmt.Errorf("error funding packet: %w", err)
		}

		lockedOutpoints = fn.Map(lockedUTXO,
			func(utxo *walletrpc.UtxoLease) wire.OutPoint {
				var hash chainhash.Hash
				copy(hash[:], utxo.Outpoint.TxidBytes)
				return wire.OutPoint{
					Hash:  hash,
					Index: utxo.Outpoint.OutputIndex,
				}
			},
		)

		// From now on, if we error out, we need to make sure we unlock
		// the UTXOs that lnd just locked for us.
		defer func() {
			if success {
				return
			}
			if hooks != nil && hooks.attemptReplaced {
				hooks.retainPending = true
				return
			}

			var releaseErr error
			for idx, utxo := range lockedUTXO {
				var lockID wtxmgr.LockID
				copy(lockID[:], utxo.Id)

				op := lockedOutpoints[idx]
				err := lndWallet.ReleaseOutput(ctx, lockID, op)
				if err != nil {
					rpcsLog.Errorf("Error unlocking lnd "+
						"UTXO %v: %v", op, err)
					releaseErr = err
				}
			}
			if releaseErr != nil && hooks != nil {
				hooks.retainPending = true
			}
		}()

		if hooks != nil && hooks.onFunded != nil {
			err = hooks.onFunded(
				effectiveCommitLockID(
					lockedUTXO, req.CustomLockId,
				),
				outpointsFromWire(lockedOutpoints),
				earliestUtxoLeaseExpiry(lockedUTXO),
			)
			if err != nil {
				return nil, fmt.Errorf("recording funded "+
					"leases: %w", err)
			}
		}
	}

	if noNewAnchorChangeRequested(req) {
		err := checkNoNewAnchorChange(pkt, fundedPacket, changeIndex)
		if err != nil {
			return nil, err
		}
	}

	// We can now update the anchor outputs as we have the final
	// commitments.
	outputCommitments, err := tapsend.CreateOutputCommitments(
		allPackets, tapsend.WithSpenderLeaves(),
	)
	if err != nil {
		return nil, fmt.Errorf("unable to create new output "+
			"commitments: %w", err)
	}

	for _, vPkt := range allPackets {
		err = tapsend.UpdateTaprootOutputKeys(
			fundedPacket, vPkt, outputCommitments,
		)
		if err != nil {
			return nil, fmt.Errorf("error updating taproot output "+
				"keys: %w", err)
		}
	}

	// We're done creating the output commitments, we can now create the
	// transition proof suffixes.
	for idx := range allPackets {
		vPkt := allPackets[idx]

		for vOutIdx := range vPkt.Outputs {
			proofSuffix, err := tapsend.CreateProofSuffix(
				fundedPacket.UnsignedTx, fundedPacket.Outputs,
				vPkt, outputCommitments, vOutIdx, allPackets,
				proofOpts...,
			)
			if err != nil {
				return nil, fmt.Errorf("unable to create "+
					"proof suffix for output %d of vPSBT "+
					"%d: %w", vOutIdx, idx, err)
			}

			vPkt.Outputs[vOutIdx].ProofSuffix = proofSuffix
		}
	}

	// We can now prepare the full answer, beginning with the serialized
	// final packet.
	response := &wrpc.CommitVirtualPsbtsResponse{
		ChangeOutputIndex: changeIndex,
	}

	response.AnchorPsbt, err = fn.Serialize(fundedPacket)
	if err != nil {
		return nil, fmt.Errorf("error serializing packet: %w", err)
	}

	// Serialize the final active and passive virtual packets.
	response.VirtualPsbts, err = encodeVirtualPackets(activePackets)
	if err != nil {
		return nil, fmt.Errorf("error encoding active packets: %w", err)
	}
	response.PassiveAssetPsbts, err = encodeVirtualPackets(passivePackets)
	if err != nil {
		return nil, fmt.Errorf("error encoding passive packets: %w",
			err)
	}

	// And finally, we need to also return the locked UTXOs. We just return
	// the outpoint, as any additional information can be fetched from the
	// lnd wallet directly (we don't want to create pass-through RPCs for
	// all those methods).
	response.LndLockedUtxos = make([]*taprpc.OutPoint, len(lockedOutpoints))
	for idx := range lockedOutpoints {
		response.LndLockedUtxos[idx] = &taprpc.OutPoint{
			Txid:        lockedOutpoints[idx].Hash[:],
			OutputIndex: lockedOutpoints[idx].Index,
		}
	}

	if hooks != nil && hooks.onResult != nil {
		err = hooks.onResult(response)
		if err != nil {
			return nil, fmt.Errorf("recording commit result: %w",
				err)
		}
	}

	// We were successful, let's cancel the UTXO release in the defer.
	success = true

	return response, nil
}

// validateInputAssets makes sure that the input assets are correct and their
// combined commitments match the inputs of the BTC level anchor transaction.

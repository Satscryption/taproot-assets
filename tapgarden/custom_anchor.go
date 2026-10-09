package tapgarden

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/mempool"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightninglabs/taproot-assets/tapsend"
	"github.com/lightningnetwork/lnd/keychain"
	"slices"
)

var customAnchorPsbtMarker = []byte{
	0xfc, 0x04, 't', 'a', 'p', 'd', 0x01,
}

// CustomAnchorLeaseID identifies wallet leases held for one mint batch.
type CustomAnchorLeaseID [32]byte

// CustomAnchorLeaser leases individual wallet inputs for custom-anchor minting.
type CustomAnchorLeaser interface {
	LeaseInput(ctx context.Context, leaseID CustomAnchorLeaseID,
		op wire.OutPoint) (bool, error)

	ReleaseInput(ctx context.Context, leaseID CustomAnchorLeaseID,
		op wire.OutPoint) error
}

// CustomAnchorBatchLeaser leases many wallet inputs in one snapshot.
type CustomAnchorBatchLeaser interface {
	LeaseInputs(ctx context.Context, leaseID CustomAnchorLeaseID,
		ops []wire.OutPoint) ([]wire.OutPoint, error)

	ReleaseInputs(ctx context.Context, leaseID CustomAnchorLeaseID,
		ops []wire.OutPoint) error
}

func markCustomAnchorPsbt(packet *psbt.Packet) {
	if isCustomAnchorPsbt(packet) {
		return
	}

	packet.Unknowns = append(packet.Unknowns, &psbt.Unknown{
		Key:   fn.CopySlice(customAnchorPsbtMarker),
		Value: []byte{1},
	})
}

func isCustomAnchorPsbt(packet *psbt.Packet) bool {
	if packet == nil {
		return false
	}

	for _, unknown := range packet.Unknowns {
		if bytes.Equal(unknown.Key, customAnchorPsbtMarker) {
			return true
		}
	}

	return false
}

func customAnchorLeaseID(batchKey *btcec.PublicKey) CustomAnchorLeaseID {
	preimage := append(
		[]byte("tapd-custom-anchor-psbt-lease-v1:"),
		batchKey.SerializeCompressed()...,
	)

	return CustomAnchorLeaseID(sha256.Sum256(preimage))
}

func customAnchorKeyDesc(chainParams address.ChainParams, packet *psbt.Packet,
	assetAnchorOutIdx uint32) (keychain.KeyDescriptor, error) {

	var zero keychain.KeyDescriptor
	if packet == nil || uint64(assetAnchorOutIdx) >=
		uint64(len(packet.Outputs)) {

		return zero, fmt.Errorf("custom anchor output metadata is missing")
	}

	pOut := packet.Outputs[assetAnchorOutIdx]
	if len(pOut.Bip32Derivation) != 1 ||
		len(pOut.TaprootBip32Derivation) != 1 {

		return zero, fmt.Errorf("custom asset anchor output must specify " +
			"exactly one BIP32 and Taproot BIP32 derivation")
	}

	bip32Derivation := pOut.Bip32Derivation[0]
	taprootDerivation := pOut.TaprootBip32Derivation[0]
	desc, err := tappsbt.KeyDescFromBip32Derivation(bip32Derivation)
	if err != nil {
		return zero, fmt.Errorf("invalid custom anchor key derivation: %w",
			err)
	}

	expectedBip32, expectedTaproot := tappsbt.Bip32DerivationFromKeyDesc(
		desc, chainParams.HDCoinType,
	)
	if !bytes.Equal(expectedBip32.PubKey, bip32Derivation.PubKey) ||
		!slices.Equal(expectedBip32.Bip32Path, bip32Derivation.Bip32Path) ||
		!bytes.Equal(
			expectedTaproot.XOnlyPubKey,
			taprootDerivation.XOnlyPubKey,
		) || !slices.Equal(
		expectedTaproot.Bip32Path, taprootDerivation.Bip32Path,
	) || len(taprootDerivation.LeafHashes) != 0 ||
		!bytes.Equal(
			pOut.TaprootInternalKey,
			taprootDerivation.XOnlyPubKey,
		) {

		return zero, fmt.Errorf("custom anchor key derivation doesn't " +
			"match its internal key or network path")
	}

	return desc, nil
}

// customGenesisPsbt validates and packages a caller-authored mint anchor
// PSBT. Unlike fundGenesisPsbt, this path doesn't ask the backing wallet to
// add or reorder anything in the packet.
func customGenesisPsbt(chainParams address.ChainParams,
	pendingBatch *MintingBatch, packet *psbt.Packet,
	assetAnchorOutIdx uint32,
	changeOutputIndex int32,
	preCommitOutputIndex fn.Option[uint32]) (FundedMintAnchorPsbt, error) {

	var zero FundedMintAnchorPsbt

	if packet == nil || packet.UnsignedTx == nil {
		return zero, fmt.Errorf("custom anchor PSBT is missing its " +
			"unsigned transaction")
	}
	if len(packet.UnsignedTx.TxIn) == 0 {
		return zero, fmt.Errorf("custom anchor PSBT must have at least " +
			"one input")
	}
	if len(packet.Inputs) != len(packet.UnsignedTx.TxIn) {
		return zero, fmt.Errorf("custom anchor PSBT input maps don't " +
			"match unsigned transaction inputs")
	}
	if len(packet.Outputs) != len(packet.UnsignedTx.TxOut) {
		return zero, fmt.Errorf("custom anchor PSBT output maps don't " +
			"match unsigned transaction outputs")
	}
	if int(assetAnchorOutIdx) >= len(packet.UnsignedTx.TxOut) {
		return zero, fmt.Errorf("asset anchor output index %d out of "+
			"range", assetAnchorOutIdx)
	}
	if changeOutputIndex < -1 ||
		changeOutputIndex >= int32(len(packet.UnsignedTx.TxOut)) {

		return zero, fmt.Errorf("change output index %d out of range",
			changeOutputIndex)
	}
	if changeOutputIndex == int32(assetAnchorOutIdx) {
		return zero, fmt.Errorf("asset anchor and change output indexes " +
			"must be distinct")
	}
	if err := packet.SanityCheck(); err != nil {
		return zero, fmt.Errorf("invalid custom anchor PSBT: %w", err)
	}
	fee, err := packet.GetTxFee()
	if err != nil {
		return zero, fmt.Errorf("custom anchor PSBT has incomplete or "+
			"invalid input values: %w", err)
	}
	if fee < 0 {
		return zero, fmt.Errorf("custom anchor PSBT outputs exceed " +
			"known input value")
	}
	anchorOutput := packet.UnsignedTx.TxOut[assetAnchorOutIdx]
	eventualAnchorOutput := tapsend.CreateDummyOutput()
	eventualAnchorOutput.Value = anchorOutput.Value
	if eventualAnchorOutput.Value <
		mempool.GetDustThreshold(eventualAnchorOutput) {

		return zero, fmt.Errorf("custom asset anchor output is dust")
	}

	for idx := range packet.Inputs {
		pIn := &packet.Inputs[idx]
		if len(pIn.PartialSigs) != 0 || len(pIn.FinalScriptSig) != 0 ||
			len(pIn.FinalScriptWitness) != 0 ||
			len(pIn.TaprootKeySpendSig) != 0 ||
			len(pIn.TaprootScriptSpendSig) != 0 {

			return zero, fmt.Errorf("custom anchor PSBT must be " +
				"unsigned before batch preparation")
		}
	}

	pOut := packet.Outputs[assetAnchorOutIdx]
	if len(pOut.TaprootInternalKey) != schnorr.PubKeyBytesLen {
		return zero, fmt.Errorf("custom asset anchor output must specify " +
			"a taproot internal key")
	}
	if _, err := schnorr.ParsePubKey(pOut.TaprootInternalKey); err != nil {
		return zero, fmt.Errorf("invalid custom asset anchor internal "+
			"key: %w", err)
	}

	funded := tapsend.FundedPsbt{
		Pkt:               packet,
		ChangeOutputIndex: changeOutputIndex,
	}
	markCustomAnchorPsbt(packet)

	var preCommitOut fn.Option[PreCommitmentOutput]
	var preCommitIdx fn.Option[uint32]
	if pendingBatch != nil && pendingBatch.SupplyCommitments {
		idx, err := preCommitOutputIndex.UnwrapOrErr(fmt.Errorf(
			"custom supply commitment batch requires a pre-commitment " +
				"output index",
		))
		if err != nil {
			return zero, err
		}
		if int(idx) >= len(packet.UnsignedTx.TxOut) ||
			idx == assetAnchorOutIdx || idx == uint32(changeOutputIndex) {

			return zero, fmt.Errorf("invalid pre-commitment output "+
				"index %d", idx)
		}

		delegationKey, err := fetchDelegationKey(pendingBatch)
		if err != nil {
			return zero, err
		}
		dKey, err := delegationKey.UnwrapOrErr(fmt.Errorf(
			"missing supply commitment delegation key",
		))
		if err != nil {
			return zero, err
		}
		expectedOutput, err := PreCommitTxOut(*dKey.PubKey)
		if err != nil {
			return zero, err
		}
		actualOutput := packet.UnsignedTx.TxOut[idx]
		if actualOutput.Value != expectedOutput.Value ||
			!bytes.Equal(actualOutput.PkScript, expectedOutput.PkScript) {

			return zero, fmt.Errorf("pre-commitment output %d doesn't "+
				"match the batch delegation key", idx)
		}

		bip32Derivation, trBip32Derivation :=
			tappsbt.Bip32DerivationFromKeyDesc(
				dKey, chainParams.HDCoinType,
			)
		pCommitOut := &packet.Outputs[idx]
		pCommitOut.Bip32Derivation = []*psbt.Bip32Derivation{bip32Derivation}
		pCommitOut.TaprootBip32Derivation = []*psbt.TaprootBip32Derivation{
			trBip32Derivation,
		}
		pCommitOut.TaprootInternalKey = trBip32Derivation.XOnlyPubKey

		groupKey, err := fetchPreCommitGroupKey(pendingBatch)
		if err != nil {
			return zero, err
		}
		preCommitOut = fn.Some(NewPreCommitmentOutput(
			idx, dKey, groupKey,
		))
		preCommitIdx = fn.Some(idx)
	} else if preCommitOutputIndex.IsSome() {
		return zero, fmt.Errorf("pre-commitment output index specified " +
			"for batch without supply commitments")
	}
	indexes := AnchorTxOutputIndexes{
		AssetAnchorOutIdx: assetAnchorOutIdx,
		ChangeOutIdx:      0,
		PreCommitOutIdx:   preCommitIdx,
	}

	return NewFundedMintAnchorPsbt(
		funded, indexes, preCommitOut,
	)
}

func acquireCustomAnchorLeases(ctx context.Context, wallet WalletAnchor,
	leaseID CustomAnchorLeaseID, packet *psbt.Packet) ([]wire.OutPoint,
	error) {

	if packet == nil || packet.UnsignedTx == nil {
		return nil, fmt.Errorf("custom anchor PSBT is missing a transaction")
	}
	ops := make([]wire.OutPoint, 0, len(packet.UnsignedTx.TxIn))
	for _, txIn := range packet.UnsignedTx.TxIn {
		ops = append(ops, txIn.PreviousOutPoint)
	}

	return leaseCustomAnchorOutpoints(ctx, wallet, leaseID, ops)
}

func leaseCustomAnchorOutpoints(ctx context.Context, wallet WalletAnchor,
	leaseID CustomAnchorLeaseID, ops []wire.OutPoint) ([]wire.OutPoint,
	error) {

	batchLeaser, ok := wallet.(CustomAnchorBatchLeaser)
	if !ok {
		return nil, fmt.Errorf("wallet does not support custom anchor leases")
	}

	seen := make(map[wire.OutPoint]struct{}, len(ops))
	for _, op := range ops {
		if _, ok := seen[op]; ok {
			return nil, fmt.Errorf("custom anchor PSBT repeats input %v", op)
		}
		seen[op] = struct{}{}
	}

	locked, err := batchLeaser.LeaseInputs(ctx, leaseID, ops)
	if err != nil {
		releaseErr := releaseCustomAnchorOutpoints(ctx, wallet, leaseID, locked)
		return nil, errors.Join(err, releaseErr)
	}

	lockedSet := make(map[wire.OutPoint]struct{}, len(locked))
	for _, op := range locked {
		if _, requested := seen[op]; !requested {
			releaseErr := releaseCustomAnchorOutpoints(
				ctx, wallet, leaseID, locked,
			)
			return nil, errors.Join(fmt.Errorf(
				"wallet returned unrequested custom anchor lease %v", op,
			), releaseErr)
		}
		if _, duplicate := lockedSet[op]; duplicate {
			releaseErr := releaseCustomAnchorOutpoints(
				ctx, wallet, leaseID, locked,
			)
			return nil, errors.Join(fmt.Errorf(
				"wallet returned duplicate custom anchor lease %v", op,
			), releaseErr)
		}
		lockedSet[op] = struct{}{}
	}

	return locked, nil
}

func releaseCustomAnchorOutpoints(ctx context.Context, wallet WalletAnchor,
	leaseID CustomAnchorLeaseID, ops []wire.OutPoint) error {

	if len(ops) == 0 {
		return nil
	}

	batchLeaser, ok := wallet.(CustomAnchorBatchLeaser)
	if !ok {
		return fmt.Errorf("wallet does not support custom anchor leases")
	}

	return batchLeaser.ReleaseInputs(ctx, leaseID, ops)
}

func releaseCustomAnchorLeases(ctx context.Context, wallet WalletAnchor,
	leaseID CustomAnchorLeaseID, funded *FundedMintAnchorPsbt) error {

	if funded == nil {
		return nil
	}

	return releaseCustomAnchorOutpoints(ctx, wallet, leaseID, funded.LockedUTXOs)
}

func releaseBatchFundingInputs(ctx context.Context, wallet WalletAnchor,
	batch *MintingBatch) {

	if batch == nil || batch.GenesisPacket == nil {
		return
	}

	var err error
	if isCustomAnchorPsbt(batch.GenesisPacket.Pkt) {
		err = releaseCustomAnchorLeases(
			ctx, wallet, customAnchorLeaseID(batch.BatchKey.PubKey),
			batch.GenesisPacket,
		)
	} else {
		err = releaseFundingInputs(ctx, wallet, &batch.GenesisPacket.FundedPsbt)
	}
	if err != nil {
		batchKeySerial := asset.ToSerialized(batch.BatchKey.PubKey)
		log.Warnf("Unable to release funding inputs of cancelled "+
			"batch (%x): %v", batchKeySerial[:], err)
	}
}

func releaseFundingInputs(ctx context.Context, wallet WalletAnchor,
	funded *tapsend.FundedPsbt) error {

	if funded == nil {
		return nil
	}

	outpoints := funded.LockedUTXOs
	if len(outpoints) == 0 && funded.Pkt != nil &&
		funded.Pkt.UnsignedTx != nil {

		txIns := funded.Pkt.UnsignedTx.TxIn
		outpoints = make([]wire.OutPoint, 0, len(txIns))
		for _, txIn := range txIns {
			outpoints = append(outpoints, txIn.PreviousOutPoint)
		}
	}

	var unlockErrs []error
	for _, outpoint := range outpoints {
		if err := wallet.UnlockInput(ctx, outpoint); err != nil {
			unlockErrs = append(unlockErrs, fmt.Errorf(
				"unable to unlock input %v: %w", outpoint, err,
			))
		}
	}

	return errors.Join(unlockErrs...)
}

func batchFundingError(ctx context.Context, wallet WalletAnchor,
	batchKey *btcec.PublicKey, funded *FundedMintAnchorPsbt,
	cause error) error {

	if funded == nil {
		return cause
	}
	if isCustomAnchorPsbt(funded.Pkt) {
		releaseErr := releaseCustomAnchorLeases(
			ctx, wallet, customAnchorLeaseID(batchKey), funded,
		)
		return errors.Join(cause, releaseErr)
	}

	cleanupCtx, cancel := context.WithTimeout(
		context.WithoutCancel(ctx), DefaultTimeout,
	)
	defer cancel()

	releaseErr := releaseFundingInputs(cleanupCtx, wallet, &funded.FundedPsbt)
	if releaseErr == nil {
		return cause
	}

	return errors.Join(cause, releaseErr)
}

// prepareBatch commits the asset tree into a caller-authored anchor PSBT and
// then pauses at the committed state so the packet can be signed externally.
func (c *ChainPlanter) prepareBatch(ctx context.Context,
	batch *MintingBatch) (*MintingBatch, error) {

	if !batch.IsFunded() || !isCustomAnchorPsbt(batch.GenesisPacket.Pkt) {
		return nil, fmt.Errorf("batch does not use a custom anchor PSBT")
	}
	if batch.State() != BatchStatePending &&
		batch.State() != BatchStateFrozen {

		return nil, fmt.Errorf("batch is not ready for preparation: %v",
			batch.State())
	}

	sealedBatch, err := c.sealBatch(ctx, SealParams{}, batch)
	if err != nil && !errors.Is(err, ErrBatchAlreadySealed) {
		return nil, err
	}
	if sealedBatch != nil {
		batch = sealedBatch
	}

	if batch.State() == BatchStatePending {
		if err := freezeMintingBatch(ctx, c.cfg.Log, batch); err != nil {
			return nil, err
		}
		batch.UpdateState(BatchStateFrozen)
	}

	caretaker := c.newCaretakerForBatch(batch, nil)
	nextState, err := caretaker.stateStep(BatchStateFrozen)
	delete(c.caretakers, asset.ToSerialized(batch.BatchKey.PubKey))
	if err != nil {
		return nil, err
	}
	if nextState != BatchStateCommitted {
		return nil, fmt.Errorf("unexpected prepared batch state: %v",
			nextState)
	}

	batch.UpdateState(BatchStateCommitted)
	return batch, nil
}

func mergeSignedCustomPsbt(stored,
	signed *psbt.Packet) (*psbt.Packet, error) {

	if stored == nil || signed == nil {
		return nil, fmt.Errorf("signed custom anchor PSBT is missing")
	}
	if err := signed.SanityCheck(); err != nil {
		return nil, fmt.Errorf("invalid signed custom anchor PSBT: %w", err)
	}
	normalizePacket := func(pkt *psbt.Packet) (*psbt.Packet, error) {
		var buf bytes.Buffer
		if err := pkt.Serialize(&buf); err != nil {
			return nil, err
		}
		return psbt.NewFromRawBytes(&buf, false)
	}
	storedNorm, err := normalizePacket(stored)
	if err != nil {
		return nil, err
	}
	signedNorm, err := normalizePacket(signed)
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(storedNorm.UnsignedTx, signedNorm.UnsignedTx) ||
		!reflect.DeepEqual(storedNorm.Outputs, signedNorm.Outputs) ||
		!reflect.DeepEqual(storedNorm.XPubs, signedNorm.XPubs) ||
		!reflect.DeepEqual(storedNorm.Unknowns, signedNorm.Unknowns) ||
		len(stored.Inputs) != len(signed.Inputs) {

		return nil, fmt.Errorf("signed custom anchor PSBT changes prepared " +
			"transaction or metadata")
	}

	hasSignature := false
	for idx := range stored.Inputs {
		storedCmp := stored.Inputs[idx]
		signedCmp := signed.Inputs[idx]
		isFinal := signedCmp.FinalScriptSig != nil ||
			signedCmp.FinalScriptWitness != nil
		if isFinal {
			if signedCmp.WitnessUtxo != nil &&
				!reflect.DeepEqual(
					storedCmp.WitnessUtxo, signedCmp.WitnessUtxo,
				) {

				return nil, fmt.Errorf("signed custom anchor PSBT " +
					"changes input UTXO")
			}
			if signedCmp.NonWitnessUtxo != nil &&
				!reflect.DeepEqual(
					storedCmp.NonWitnessUtxo,
					signedCmp.NonWitnessUtxo,
				) {

				return nil, fmt.Errorf("signed custom anchor PSBT " +
					"changes input UTXO")
			}
			if signedCmp.WitnessUtxo == nil &&
				signedCmp.NonWitnessUtxo == nil {

				return nil, fmt.Errorf("finalized custom anchor PSBT " +
					"drops input UTXO")
			}

			hasSignature = true
			continue
		}

		storedCmp.PartialSigs = nil
		storedCmp.FinalScriptSig = nil
		storedCmp.FinalScriptWitness = nil
		storedCmp.TaprootKeySpendSig = nil
		storedCmp.TaprootScriptSpendSig = nil
		signedCmp.PartialSigs = nil
		signedCmp.FinalScriptSig = nil
		signedCmp.FinalScriptWitness = nil
		signedCmp.TaprootKeySpendSig = nil
		signedCmp.TaprootScriptSpendSig = nil

		if !reflect.DeepEqual(storedCmp, signedCmp) {
			return nil, fmt.Errorf("signed custom anchor PSBT changes input "+
				"%d metadata", idx)
		}

		src := &signed.Inputs[idx]
		if len(src.PartialSigs) != 0 || src.FinalScriptSig != nil ||
			src.FinalScriptWitness != nil ||
			len(src.TaprootKeySpendSig) != 0 ||
			len(src.TaprootScriptSpendSig) != 0 {

			hasSignature = true
		}
	}

	if !hasSignature {
		return nil, fmt.Errorf("signed custom anchor PSBT has no signatures")
	}

	var buf bytes.Buffer
	if err := stored.Serialize(&buf); err != nil {
		return nil, err
	}
	merged, err := psbt.NewFromRawBytes(&buf, false)
	if err != nil {
		return nil, err
	}
	for idx := range merged.Inputs {
		src := &signed.Inputs[idx]
		dst := &merged.Inputs[idx]
		dst.PartialSigs = src.PartialSigs
		dst.FinalScriptSig = src.FinalScriptSig
		dst.FinalScriptWitness = src.FinalScriptWitness
		dst.TaprootKeySpendSig = src.TaprootKeySpendSig
		dst.TaprootScriptSpendSig = src.TaprootScriptSpendSig
	}

	return merged, nil
}

func validateFinalizedAnchorPsbt(packet *psbt.Packet) error {
	tx, err := psbt.Extract(packet)
	if err != nil {
		return err
	}

	prevOuts := txscript.NewMultiPrevOutFetcher(nil)
	for idx := range packet.Inputs {
		pIn := &packet.Inputs[idx]
		var prevOut *wire.TxOut
		switch {
		case pIn.WitnessUtxo != nil:
			prevOut = pIn.WitnessUtxo

		case pIn.NonWitnessUtxo != nil:
			outpoint := tx.TxIn[idx].PreviousOutPoint
			if int(outpoint.Index) >= len(pIn.NonWitnessUtxo.TxOut) ||
				pIn.NonWitnessUtxo.TxHash() != outpoint.Hash {

				return fmt.Errorf("invalid non-witness UTXO for input %d",
					idx)
			}
			prevOut = pIn.NonWitnessUtxo.TxOut[outpoint.Index]

		default:
			return fmt.Errorf("missing UTXO for input %d", idx)
		}

		prevOuts.AddPrevOut(tx.TxIn[idx].PreviousOutPoint, prevOut)
	}

	sigHashes := txscript.NewTxSigHashes(tx, prevOuts)
	for idx := range tx.TxIn {
		prevOut := prevOuts.FetchPrevOutput(
			tx.TxIn[idx].PreviousOutPoint,
		)
		vm, err := txscript.NewEngine(
			prevOut.PkScript, tx, idx, txscript.StandardVerifyFlags,
			nil, sigHashes, prevOut.Value, prevOuts,
		)
		if err != nil {
			return fmt.Errorf("unable to validate input %d: %w", idx,
				err)
		}
		if err := vm.Execute(); err != nil {
			return fmt.Errorf("invalid witness for input %d: %w", idx,
				err)
		}
	}

	return nil
}

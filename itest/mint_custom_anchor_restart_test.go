//nolint:lll
package itest

import (
	"bytes"
	"context"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
	"github.com/stretchr/testify/require"
)

// testMintCustomAnchorPsbtRestart stops tapd after PrepareBatch and verifies
// that restart does not wallet-sign the prepared packet. Finalization still
// succeeds via an externally signed PSBT. The anchor output is at index 1.
func testMintCustomAnchorPsbtRestart(t *harnessTest) {
	var (
		ctx       = context.Background()
		aliceTapd = t.tapd
		aliceLnd  = t.tapd.cfg.LndNode
		miner     = t.lndHarness.Miner()
	)

	mintReq := CopyRequest(simpleAssets[0])
	mintReq.Asset.Name = "issue-721-custom-anchor-restart"
	mintReq.Asset.Amount = 50
	mintReqs := []*mintrpc.MintAssetRequest{mintReq}

	BuildMintingBatch(t.t, aliceTapd, mintReqs)

	anchorKeyResp := aliceLnd.RPC.DeriveNextKey(&walletrpc.KeyReq{
		KeyFamily: int32(asset.TaprootAssetsKeyFamily),
	})
	anchorInternalKey, err := btcec.ParsePubKey(anchorKeyResp.RawKeyBytes)
	require.NoError(t.t, err)
	anchorOutputKey := txscript.ComputeTaprootKeyNoScript(anchorInternalKey)
	anchorScript, err := txscript.PayToTaprootScript(anchorOutputKey)
	require.NoError(t.t, err)

	const anchorValue = int64(10_000)
	const anchorOutIdx = uint32(1)

	tx := wire.NewMsgTx(2)
	tx.AddTxOut(&wire.TxOut{
		Value:    0,
		PkScript: []byte{txscript.OP_RETURN},
	})
	tx.AddTxOut(&wire.TxOut{
		Value:    anchorValue,
		PkScript: anchorScript,
	})
	template, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t.t, err)
	anchorKeyDesc := keychain.KeyDescriptor{
		PubKey: anchorInternalKey,
		KeyLocator: keychain.KeyLocator{
			Family: keychain.KeyFamily(anchorKeyResp.KeyLoc.KeyFamily),
			Index:  uint32(anchorKeyResp.KeyLoc.KeyIndex),
		},
	}
	bip32Derivation, taprootDerivation :=
		tappsbt.Bip32DerivationFromKeyDesc(
			anchorKeyDesc, harnessNetParams.HDCoinType,
		)
	template.Outputs[anchorOutIdx].Bip32Derivation = []*psbt.Bip32Derivation{
		bip32Derivation,
	}
	template.Outputs[anchorOutIdx].TaprootBip32Derivation =
		[]*psbt.TaprootBip32Derivation{taprootDerivation}
	template.Outputs[anchorOutIdx].TaprootInternalKey =
		taprootDerivation.XOnlyPubKey

	templateBytes, err := fn.Serialize(template)
	require.NoError(t.t, err)
	fundResp := aliceLnd.RPC.FundPsbt(&walletrpc.FundPsbtRequest{
		Template: &walletrpc.FundPsbtRequest_CoinSelect{
			CoinSelect: &walletrpc.PsbtCoinSelect{
				Psbt: templateBytes,
				ChangeOutput: &walletrpc.PsbtCoinSelect_Add{
					Add: true,
				},
			},
		},
		Fees: &walletrpc.FundPsbtRequest_SatPerVbyte{
			SatPerVbyte: 2,
		},
		MinConfs:    1,
		ChangeType:  walletrpc.ChangeAddressType_CHANGE_ADDRESS_TYPE_P2TR,
		MaxFeeRatio: 1,
	})
	for _, lease := range fundResp.LockedUtxos {
		_, err := aliceLnd.RPC.WalletKit.ReleaseOutput(
			ctx, &walletrpc.ReleaseOutputRequest{
				Id:       lease.Id,
				Outpoint: lease.Outpoint,
			},
		)
		require.NoError(t.t, err)
	}

	_, err = aliceTapd.FundBatch(ctx, &mintrpc.FundBatchRequest{
		AnchorPsbt:             fundResp.FundedPsbt,
		AssetAnchorOutputIndex: anchorOutIdx,
		ChangeOutputIndex:      fundResp.ChangeOutputIndex,
	})
	require.NoError(t.t, err)

	prepareResp, err := aliceTapd.PrepareBatch(
		ctx, &mintrpc.PrepareBatchRequest{},
	)
	require.NoError(t.t, err)
	require.Equal(
		t.t, mintrpc.BatchState_BATCH_STATE_COMMITTED,
		prepareResp.Batch.State,
	)
	batchKey := prepareResp.Batch.BatchKey

	require.NoError(t.t, aliceTapd.stop(false))
	require.NoError(t.t, aliceTapd.start(false))

	listResp, err := aliceTapd.ListBatches(ctx, &mintrpc.ListBatchRequest{
		Filter: &mintrpc.ListBatchRequest_BatchKey{BatchKey: batchKey},
	})
	require.NoError(t.t, err)
	require.Len(t.t, listResp.Batches, 1)
	require.Equal(
		t.t, mintrpc.BatchState_BATCH_STATE_COMMITTED,
		listResp.Batches[0].Batch.State,
	)

	preparedPacket, err := psbt.NewFromRawBytes(
		bytes.NewReader(listResp.Batches[0].Batch.BatchPsbt), false,
	)
	require.NoError(t.t, err)
	signedPacket := FinalizePacket(t.t, aliceLnd.RPC, preparedPacket)
	signedBytes, err := fn.Serialize(signedPacket)
	require.NoError(t.t, err)

	finalizeResp, err := aliceTapd.FinalizeBatch(
		ctx, &mintrpc.FinalizeBatchRequest{SignedPsbt: signedBytes},
	)
	require.NoError(t.t, err)
	require.Equal(
		t.t, mintrpc.BatchState_BATCH_STATE_BROADCAST,
		finalizeResp.Batch.State,
	)

	_, err = aliceTapd.FinalizeBatch(
		ctx, &mintrpc.FinalizeBatchRequest{SignedPsbt: signedBytes},
	)
	require.NoError(t.t, err)

	hashes, err := WaitForNTxsInMempool(miner, 1, defaultWaitTimeout)
	require.NoError(t.t, err)
	block := MineBlocks(t.t, miner, 1, 1)[0]
	WaitForBatchState(
		t.t, ctx, aliceTapd, defaultWaitTimeout, batchKey,
		mintrpc.BatchState_BATCH_STATE_FINALIZED,
	)
	AssertAssetsMinted(
		t.t, aliceTapd, mintReqs, *hashes[0], block.BlockHash(),
	)
}

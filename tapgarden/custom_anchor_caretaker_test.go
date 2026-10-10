package tapgarden

import (
	"context"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
)

func randBatchKey(t *testing.T) keychain.KeyDescriptor {
	t.Helper()

	priv, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	return keychain.KeyDescriptor{PubKey: priv.PubKey()}
}

// TestCustomAnchorCommittedStepSkipsWalletSign proves an unsigned custom-anchor
// PSBT at COMMITTED does not invoke SignAndFinalizePsbt (restart-safe pause).
func TestCustomAnchorCommittedStepSkipsWalletSign(t *testing.T) {
	pkt := testCustomAnchorPacket(t)
	funded, err := customGenesisPsbt(
		address.TestNet3Tap, nil, pkt, 0, -1, noneUint32(),
	)
	require.NoError(t, err)

	wallet := NewMockWalletAnchor()
	chain := NewMockChainBridge()

	batch := &MintingBatch{
		BatchKey:      randBatchKey(t),
		Seedlings:     map[string]*Seedling{},
		AssetMetas:    make(AssetMetas),
		GenesisPacket: &funded,
	}
	batch.UpdateState(BatchStateCommitted)

	caretaker := NewBatchCaretaker(&BatchCaretakerConfig{
		Batch: batch,
		GardenKit: GardenKit{
			Wallet:      wallet,
			ChainBridge: chain,
		},
	})

	next, err := caretaker.stateStep(BatchStateCommitted)
	require.NoError(t, err)
	require.Equal(t, BatchStateCommitted, next)

	select {
	case <-wallet.SignPsbtSignal:
		t.Fatal("wallet must not sign a prepared custom-anchor PSBT")
	case <-time.After(50 * time.Millisecond):
	}
}

// TestCustomAnchorBroadcastWatchesAssetAnchorOutput proves confirmation
// registration uses the asset anchor output script, not TxOut[0].
func TestCustomAnchorBroadcastWatchesAssetAnchorOutput(t *testing.T) {
	const anchorIdx = uint32(1)

	pkt := testCustomAnchorPacket(t)
	anchorScript := pkt.UnsignedTx.TxOut[0].PkScript
	changeAddr, err := btcutil.NewAddressScriptHash(
		[]byte("change"), &chaincfg.RegressionNetParams,
	)
	require.NoError(t, err)
	changeScript, err := txscript.PayToAddrScript(changeAddr)
	require.NoError(t, err)

	pkt.UnsignedTx.TxOut = []*wire.TxOut{
		{Value: 5000, PkScript: changeScript},
		{Value: pkt.UnsignedTx.TxOut[0].Value, PkScript: anchorScript},
	}
	pkt.Outputs = []psbt.POutput{{}, {}}
	markCustomAnchorPsbt(pkt)
	pkt.Inputs[0].FinalScriptWitness = []byte{1, 0}

	funded := FundedMintAnchorPsbt{
		FundedPsbt:        fundedPsbt(pkt),
		AssetAnchorOutIdx: anchorIdx,
	}

	wallet := NewMockWalletAnchor()
	chain := NewMockChainBridge()

	batch := &MintingBatch{
		BatchKey:      randBatchKey(t),
		Seedlings:     map[string]*Seedling{},
		AssetMetas:    make(AssetMetas),
		GenesisPacket: &funded,
	}
	batch.UpdateState(BatchStateBroadcast)

	caretaker := NewBatchCaretaker(&BatchCaretakerConfig{
		Batch: batch,
		GardenKit: GardenKit{
			Wallet:      wallet,
			ChainBridge: chain,
		},
		BroadcastCompleteChan: make(chan struct{}, 1),
		BroadcastErrChan:      make(chan error, 1),
	})
	caretaker.anchorOutputIndex = anchorIdx

	confChecked := make(chan struct{})
	go func() {
		<-chain.PublishReq
	}()
	go func() {
		<-chain.ConfReqSignal
		require.Equal(t, anchorScript, chain.LastConfPkScript)
		close(confChecked)
	}()

	_, err = caretaker.stateStep(BatchStateBroadcast)
	require.NoError(t, err)

	select {
	case <-confChecked:
	case <-time.After(2 * time.Second):
		t.Fatal("expected confirmation registration for anchor output")
	}
}

// TestCancelPreparedCustomAnchorBatch rejects cancellation after prepare.
func TestCancelPreparedCustomAnchorBatch(t *testing.T) {
	planter := &ChainPlanter{}
	batchKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pkt := testCustomAnchorPacket(t)
	funded, err := customGenesisPsbt(
		address.TestNet3Tap, nil, pkt, 0, -1, noneUint32(),
	)
	require.NoError(t, err)

	planter.pendingBatch = &MintingBatch{
		BatchKey: keychain.KeyDescriptor{PubKey: batchKey.PubKey()},
		Seedlings:     map[string]*Seedling{},
		GenesisPacket: &funded,
	}
	planter.pendingBatch.UpdateState(BatchStateCommitted)

	err = planter.cancelMintingBatch(
		context.Background(), planter.pendingBatch.BatchKey.PubKey,
	)
	require.ErrorContains(t, err, "not cancellable")
}

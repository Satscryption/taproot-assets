package tapdb

import (
	"bytes"
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/btcutil/txsort"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapsend"
	"github.com/lightninglabs/taproot-assets/universe/supplycommit"
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/stretchr/testify/require"
)

// rebuildWallet funds and signs a commitment without dropping the
// pre-commit inputs the state machine already added.
type rebuildWallet struct{}

func (rebuildWallet) FundPsbt(_ context.Context, packet *psbt.Packet,
	_ uint32, _ chainfee.SatPerKWeight, _ int32) (*tapsend.FundedPsbt,
	error) {

	funded := packet.UnsignedTx.Copy()
	funded.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  chainhash.Hash{0x01},
			Index: 0,
		},
	})
	pkt, err := psbt.NewFromUnsignedTx(funded)
	if err != nil {
		return nil, err
	}

	return &tapsend.FundedPsbt{
		Pkt:               pkt,
		ChangeOutputIndex: -1,
	}, nil
}

func (rebuildWallet) SignPsbt(_ context.Context,
	pkt *psbt.Packet) (*psbt.Packet, error) {

	signed, err := psbt.NewFromUnsignedTx(pkt.UnsignedTx)
	if err != nil {
		return nil, err
	}
	// A one-element witness stack: item count, item length, item.
	for i := range signed.Inputs {
		signed.Inputs[i].FinalScriptWitness = []byte{0x01, 0x01, 0x01}
	}

	txCopy := pkt.UnsignedTx.Copy()
	txsort.InPlaceSort(txCopy)
	signed.UnsignedTx = txCopy

	return signed, nil
}

func (rebuildWallet) ImportTaprootOutput(_ context.Context,
	pub *btcec.PublicKey) (btcutil.Address, error) {

	return btcutil.NewAddressTaproot(
		pub.SerializeCompressed()[1:], &chaincfg.RegressionNetParams,
	)
}

func (rebuildWallet) UnlockInput(context.Context, wire.OutPoint) error {
	return nil
}

type rebuildKeyRing struct{}

func (rebuildKeyRing) DeriveNextTaprootAssetKey(
	context.Context) (keychain.KeyDescriptor, error) {

	priv, err := btcec.NewPrivateKey()
	if err != nil {
		return keychain.KeyDescriptor{}, err
	}

	return keychain.KeyDescriptor{
		KeyLocator: keychain.KeyLocator{
			Family: keychain.KeyFamily(212),
			Index:  1,
		},
		PubKey: priv.PubKey(),
	}, nil
}

// rebuildChain serves the two chain calls the commitment builder makes.
type rebuildChain struct{}

func (rebuildChain) GenFileChainLookup(*proof.File) asset.ChainLookup {
	return nil
}

func (rebuildChain) GenProofChainLookup(*proof.Proof) (asset.ChainLookup,
	error) {

	return nil, nil
}

func (rebuildChain) RegisterConfirmationsNtfn(context.Context,
	*chainhash.Hash, []byte, uint32, uint32, bool,
	chan struct{}) (*chainntnfs.ConfirmationEvent, chan error, error) {

	return nil, nil, nil
}

func (rebuildChain) RegisterBlockEpochNtfn(context.Context) (chan int32,
	chan error, error) {

	return nil, nil, nil
}

func (rebuildChain) GetBlock(context.Context,
	chainhash.Hash) (*wire.MsgBlock, error) {

	return nil, nil
}

func (rebuildChain) GetBlockByHeight(context.Context,
	int64) (*wire.MsgBlock, error) {

	return nil, nil
}

func (rebuildChain) GetBlockHash(context.Context, int64) (chainhash.Hash,
	error) {

	return chainhash.Hash{}, nil
}

func (rebuildChain) VerifyBlock(context.Context, wire.BlockHeader,
	uint32) error {

	return nil
}

func (rebuildChain) CurrentHeight(context.Context) (uint32, error) {
	return 200, nil
}

func (rebuildChain) GetBlockTimestamp(context.Context, uint32) (int64,
	error) {

	return 0, nil
}

func (rebuildChain) GetBlockHeaderByHeight(context.Context,
	int64) (*wire.BlockHeader, error) {

	return nil, nil
}

func (rebuildChain) PublishTransaction(context.Context, *wire.MsgTx,
	string) error {

	return nil
}

func (rebuildChain) EstimateFee(context.Context,
	uint32) (chainfee.SatPerKWeight, error) {

	return chainfee.FeePerKwFloor, nil
}

type rebuildDaemon struct {
	broadcast chan *wire.MsgTx
}

func (d rebuildDaemon) Start() error { return nil }

func (d rebuildDaemon) Stop() error { return nil }

func (d rebuildDaemon) BroadcastTransaction(tx *wire.MsgTx,
	_ string) error {

	d.broadcast <- tx.Copy()
	return nil
}

func (d rebuildDaemon) RegisterConfirmationsNtfn(*chainhash.Hash, []byte,
	uint32, uint32, ...chainntnfs.NotifierOption) (
	*chainntnfs.ConfirmationEvent, error) {

	return &chainntnfs.ConfirmationEvent{
		Confirmed: make(chan *chainntnfs.TxConfirmation),
	}, nil
}

func (d rebuildDaemon) RegisterSpendNtfn(*wire.OutPoint, []byte,
	uint32) (*chainntnfs.SpendEvent, error) {

	return &chainntnfs.SpendEvent{
		Spend: make(chan *chainntnfs.SpendDetail),
	}, nil
}

func (d rebuildDaemon) SendMessages(btcec.PublicKey,
	[]lnwire.Message) error {

	return nil
}

type rebuildIgnoreCache struct{}

func (rebuildIgnoreCache) InvalidateCache(btcec.PublicKey) {}

type rebuildAssetLookup struct{}

func (rebuildAssetLookup) FetchSupplyCommitAssets(context.Context,
	bool) ([]btcec.PublicKey, error) {

	return nil, nil
}

func (rebuildAssetLookup) QueryAssetGroupByID(context.Context,
	asset.ID) (*asset.AssetGroup, error) {

	return nil, nil
}

func (rebuildAssetLookup) QueryAssetGroupByGroupKey(context.Context,
	*btcec.PublicKey) (*asset.AssetGroup, error) {

	return nil, nil
}

func (rebuildAssetLookup) FetchAssetMetaForAsset(context.Context,
	asset.ID) (*proof.MetaReveal, error) {

	priv, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, err
	}

	return &proof.MetaReveal{
		UniverseCommitments: true,
		DelegationKey:       fn.Some(*priv.PubKey()),
	}, nil
}

func (rebuildAssetLookup) FetchInternalKeyLocator(context.Context,
	*btcec.PublicKey) (keychain.KeyLocator, error) {

	return keychain.KeyLocator{}, nil
}

type rebuildSyncer struct{}

func (rebuildSyncer) PushSupplyCommitment(context.Context, asset.Specifier,
	supplycommit.RootCommitment, supplycommit.SupplyLeaves,
	supplycommit.ChainProof, []url.URL) (map[string]error, error) {

	return nil, nil
}

// TestMigration61RebuildsValidCommitment abandons a commitment that
// spends neither a pre-commit nor a confirmed commitment, then starts
// the supply-commit manager the way a restarted node does. The next
// tick rebuilds a commitment that spends the caller-selected pre-commit
// output and broadcasts it.
func TestMigration61RebuildsValidCommitment(t *testing.T) {
	h := newSupplyCommitTestHarness(t)
	const preCommitIdx = int32(1)
	preOut, mintTx, mintChainID := insertCustomGenesisPreCommit(
		t, h, preCommitIdx,
	)
	transferID := retargetGenesisAnchor(t, h, mintTx)
	assertGenesisAnchorID(
		t, h, mintTx.TxIn[0].PreviousOutPoint, transferID,
	)

	err := h.commitMachine.InsertPendingUpdate(
		h.ctx, h.assetSpec, h.randMintEvent(),
	)
	require.NoError(t, err)
	bogus := test.RandOp(t)
	signedCommitTx(t, h, bogus)
	h.assertCurrentStateIs(&supplycommit.CommitBroadcastState{})

	err = repairGenesisAnchorMigration(h.ctx, h.db)
	require.NoError(t, err)

	assertGenesisAnchorID(
		t, h, mintTx.TxIn[0].PreviousOutPoint, mintChainID,
	)
	h.assertCurrentStateIs(&supplycommit.UpdatesPendingState{})
	transition := h.assertPendingTransitionExists()
	require.False(t, transition.NewCommitmentID.Valid)
	require.False(t, transition.PendingCommitTxnID.Valid)
	fetched := h.currentTransition().UnwrapOrFail(t)
	require.Len(t, fetched.PendingUpdates, 1)

	daemon := rebuildDaemon{
		broadcast: make(chan *wire.MsgTx, 1),
	}
	mgr := supplycommit.NewManager(supplycommit.ManagerCfg{
		TreeView:           h.commitTreeStore,
		Commitments:        h.commitMachine,
		Wallet:             rebuildWallet{},
		AssetLookup:        rebuildAssetLookup{},
		KeyRing:            rebuildKeyRing{},
		Chain:              rebuildChain{},
		SupplySyncer:       rebuildSyncer{},
		DaemonAdapters:     daemon,
		StateLog:           h.commitMachine,
		ChainParams:        chaincfg.RegressionNetParams,
		IgnoreCheckerCache: rebuildIgnoreCache{},
	})
	require.NoError(t, mgr.Start())
	defer func() {
		require.NoError(t, mgr.Stop())
	}()

	err = mgr.SendEvent(h.ctx, h.assetSpec, &supplycommit.CommitTickEvent{})
	require.NoError(t, err)

	var broadcast *wire.MsgTx
	select {
	case broadcast = <-daemon.broadcast:
	case <-time.After(20 * time.Second):
		t.Fatal("node did not broadcast a rebuilt commitment")
	}

	spendsPreCommit := false
	for _, in := range broadcast.TxIn {
		if in.PreviousOutPoint == preOut {
			spendsPreCommit = true
		}
		require.NotEqual(t, bogus, in.PreviousOutPoint)
	}
	require.True(t, spendsPreCommit)
	require.Equal(t, uint32(preCommitIdx), preOut.Index)

	h.assertCurrentStateIs(&supplycommit.CommitBroadcastState{})
	kept := h.assertPendingTransitionExists()
	require.True(t, kept.NewCommitmentID.Valid)

	chainTx, err := h.fetchChainTxByID(kept.PendingCommitTxnID.Int64)
	require.NoError(t, err)
	var stored wire.MsgTx
	err = stored.Deserialize(bytes.NewReader(chainTx.RawTx))
	require.NoError(t, err)
	require.Equal(t, broadcast.TxHash(), stored.TxHash())
}

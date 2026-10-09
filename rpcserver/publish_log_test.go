package rpcserver

import (
	"bytes"
	"context"
	"sync/atomic"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/tapconfig"
	"github.com/lightninglabs/taproot-assets/tapfreighter"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	wrpc "github.com/lightninglabs/taproot-assets/taprpc/assetwalletrpc"
	"github.com/stretchr/testify/require"
)

// loggedPublishPorter serves one already-logged transfer and counts
// shipment requests. It embeds Porter so only the methods this RPC
// calls need to be implemented.
type loggedPublishPorter struct {
	tapfreighter.Porter

	logged    *tapfreighter.OutboundParcel
	shipments atomic.Int32
}

func (p *loggedPublishPorter) QueryParcels(_ context.Context,
	anchorTxHash fn.Option[chainhash.Hash], _ bool) (
	[]*tapfreighter.OutboundParcel, error) {

	if p.logged == nil || p.logged.AnchorTx == nil {
		return nil, nil
	}

	var matched []*tapfreighter.OutboundParcel
	anchorTxHash.WhenSome(func(hash chainhash.Hash) {
		if p.logged.AnchorTx.TxHash() == hash {
			matched = append(matched, p.logged)
		}
	})

	return matched, nil
}

func (p *loggedPublishPorter) RequestShipment(
	tapfreighter.Parcel) (*tapfreighter.OutboundParcel, error) {

	p.shipments.Add(1)

	return p.logged, nil
}

// finalizedAnchorPSBT returns a PSBT Extract can finalize, plus that
// final transaction. The witness is an empty stack; the txid does not
// cover it.
func finalizedAnchorPSBT(t *testing.T) (*psbt.Packet, *wire.MsgTx) {
	t.Helper()

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{})
	tx.AddTxOut(&wire.TxOut{
		Value:    1_000,
		PkScript: []byte{0x51},
	})

	pkt, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)

	pkt.Inputs[0].WitnessUtxo = &wire.TxOut{
		Value:    2_000,
		PkScript: []byte{0x51},
	}
	pkt.Inputs[0].FinalScriptWitness = []byte{0x00}

	finalTx, err := psbt.Extract(pkt)
	require.NoError(t, err)

	return pkt, finalTx
}

// incompleteVirtualPacket encodes a virtual packet whose output has no
// asset. Input validation dereferences that asset, so a call that still
// validates this packet panics.
func incompleteVirtualPacket(t *testing.T) []byte {
	t.Helper()

	key, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	raw, err := tappsbt.Encode(&tappsbt.VPacket{
		ChainParams: &address.RegressionNetTap,
		Outputs: []*tappsbt.VOutput{{
			ScriptKey: asset.ScriptKey{
				PubKey: key.PubKey(),
			},
		}},
	})
	require.NoError(t, err)

	return raw
}

func publishAndLogRequest(t *testing.T, pkt *psbt.Packet,
	rawVirtual []byte) *wrpc.PublishAndLogRequest {

	t.Helper()

	var buf bytes.Buffer
	require.NoError(t, pkt.Serialize(&buf))

	return &wrpc.PublishAndLogRequest{
		AnchorPsbt:   buf.Bytes(),
		VirtualPsbts: [][]byte{rawVirtual},
		RequestId:    []byte("req-1"),
		Label:        "retry",
	}
}

// TestPublishAndLogTransferSkipsValidationWhenLogged checks that a
// repeat publish of an already-logged anchor returns that transfer.
// The virtual packet would panic in input validation, so success means
// validation was skipped.
func TestPublishAndLogTransferSkipsValidationWhenLogged(t *testing.T) {
	t.Parallel()

	pkt, finalTx := finalizedAnchorPSBT(t)
	porter := &loggedPublishPorter{
		logged: &tapfreighter.OutboundParcel{
			AnchorTx: finalTx,
			Label:    "logged-transfer",
		},
	}
	server := &RPCServer{cfg: &tapconfig.Config{
		ChainPorter:    porter,
		DatabaseConfig: &tapconfig.DatabaseConfig{},
	}}

	resp, err := server.PublishAndLogTransfer(
		context.Background(),
		publishAndLogRequest(t, pkt, incompleteVirtualPacket(t)),
	)
	require.NoError(t, err)
	anchorHash := finalTx.TxHash()
	require.Equal(t, anchorHash[:], resp.Transfer.AnchorTxHash)
	require.Equal(t, "logged-transfer", resp.Transfer.Label)
	require.Equal(t, int32(1), porter.shipments.Load())
}

// TestPublishAndLogTransferValidatesWhenUnlogged checks that a first
// publish still validates. The incomplete packet panics there, and the
// porter is not asked to ship it.
func TestPublishAndLogTransferValidatesWhenUnlogged(t *testing.T) {
	t.Parallel()

	pkt, _ := finalizedAnchorPSBT(t)
	porter := &loggedPublishPorter{}
	server := &RPCServer{cfg: &tapconfig.Config{
		ChainPorter:    porter,
		DatabaseConfig: &tapconfig.DatabaseConfig{},
	}}

	require.Panics(t, func() {
		_, _ = server.PublishAndLogTransfer(
			context.Background(),
			publishAndLogRequest(
				t, pkt, incompleteVirtualPacket(t),
			),
		)
	})
	require.Zero(t, porter.shipments.Load())
}

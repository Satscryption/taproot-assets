package rpcserver

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
	wrpc "github.com/lightninglabs/taproot-assets/taprpc/assetwalletrpc"
	"github.com/stretchr/testify/require"
)

// testPacket returns a PSBT whose outputs differ in both value and script,
// so a reorder or a script-only edit is visible to the comparison.
func testPacket(t *testing.T, numOutputs int) *psbt.Packet {
	t.Helper()

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{})
	for i := 0; i < numOutputs; i++ {
		tx.AddTxOut(&wire.TxOut{
			Value:    int64(1000 + i),
			PkScript: []byte{0x51, byte(i)},
		})
	}

	pkt, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)

	return pkt
}

func clonePacket(t *testing.T, pkt *psbt.Packet) *psbt.Packet {
	t.Helper()

	raw, err := pkt.B64Encode()
	require.NoError(t, err)

	clone, err := psbt.NewFromRawBytes(bytes.NewReader([]byte(raw)), true)
	require.NoError(t, err)

	return clone
}

// anchorChangeCase is one CommitVirtualPsbts add=false comparison.
type anchorChangeCase struct {
	name        string
	template    int
	funded      int
	changeIndex int32
	alterValue  int
	alterScript int
	reorder     bool
	expectErr   bool
}

// TestCheckNoNewAnchorChange makes sure the add=false guard for
// CommitVirtualPsbts (taproot-assets#2209) fails closed whenever lnd changed
// the output set of the anchor template and only passes if it is untouched.
// Comparison is positional: values and pk scripts must match in order.
func TestCheckNoNewAnchorChange(t *testing.T) {
	t.Parallel()

	testCases := []anchorChangeCase{{
		name:        "unchanged outputs, no change index",
		template:    2,
		funded:      2,
		changeIndex: -1,
		alterValue:  -1,
		alterScript: -1,
	}, {
		name:        "change output appended",
		template:    2,
		funded:      3,
		changeIndex: 2,
		alterValue:  -1,
		alterScript: -1,
		expectErr:   true,
	}, {
		name:        "change index reported without new output",
		template:    2,
		funded:      2,
		changeIndex: 1,
		alterValue:  -1,
		alterScript: -1,
		expectErr:   true,
	}, {
		name:        "output appended without change index",
		template:    1,
		funded:      2,
		changeIndex: -1,
		alterValue:  -1,
		alterScript: -1,
		expectErr:   true,
	}, {
		name:        "output removed",
		template:    2,
		funded:      1,
		changeIndex: -1,
		alterValue:  -1,
		alterScript: -1,
		expectErr:   true,
	}, {
		name:        "template output value altered in place",
		template:    2,
		funded:      2,
		changeIndex: -1,
		alterValue:  1,
		alterScript: -1,
		expectErr:   true,
	}, {
		name:        "template output script altered in place",
		template:    2,
		funded:      2,
		changeIndex: -1,
		alterValue:  -1,
		alterScript: 0,
		expectErr:   true,
	}, {
		name:        "outputs reordered",
		template:    2,
		funded:      2,
		changeIndex: -1,
		alterValue:  -1,
		alterScript: -1,
		reorder:     true,
		expectErr:   true,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			template := testPacket(t, tc.template)
			funded := fundedPacket(t, template, tc)

			err := checkNoNewAnchorChange(
				template, funded, tc.changeIndex,
			)
			if !tc.expectErr {
				require.NoError(t, err)
				return
			}

			require.ErrorIs(t, err, ErrAnchorChangeAdded)
			require.ErrorContains(t, err, "#2209")
			require.EqualError(t, err, fmt.Sprintf(
				"unexpected anchor change output: "+
					"anchor_change_output add=false "+
					"cannot be honored, lnd changed "+
					"the anchor output set (change "+
					"output index %d, outputs %d -> "+
					"%d); use skip_funding=true with "+
					"caller-supplied inputs or "+
					"add=true (see lightninglabs/"+
					"taproot-assets#2209)",
				tc.changeIndex, tc.template, tc.funded,
			))
		})
	}
}

// fundedPacket builds the funded side of an anchor-change comparison.
func fundedPacket(t *testing.T, template *psbt.Packet,
	tc anchorChangeCase) *psbt.Packet {

	t.Helper()

	switch {
	case tc.reorder:
		funded := clonePacket(t, template)
		outs := funded.UnsignedTx.TxOut
		outs[0], outs[1] = outs[1], outs[0]

		return funded

	case tc.alterValue >= 0:
		funded := clonePacket(t, template)
		funded.UnsignedTx.TxOut[tc.alterValue].Value = 999

		return funded

	case tc.alterScript >= 0:
		funded := clonePacket(t, template)
		out := funded.UnsignedTx.TxOut[tc.alterScript]
		out.PkScript = []byte{0xff}

		return funded

	case tc.funded == tc.template:
		return template

	default:
		funded := testPacket(t, tc.funded)
		limit := tc.template
		if tc.funded < limit {
			limit = tc.funded
		}
		for idx := 0; idx < limit; idx++ {
			funded.UnsignedTx.TxOut[idx] =
				template.UnsignedTx.TxOut[idx]
		}

		return funded
	}
}

// TestCheckNoNewAnchorChangeNilScript locks the script comparison:
// bytes.Equal treats a nil pk script and an empty one as the same output.
func TestCheckNoNewAnchorChangeNilScript(t *testing.T) {
	t.Parallel()

	template := testPacket(t, 1)
	template.UnsignedTx.TxOut[0].PkScript = nil

	funded := clonePacket(t, template)
	funded.UnsignedTx.TxOut[0].PkScript = []byte{}

	err := checkNoNewAnchorChange(template, funded, -1)
	require.NoError(t, err)
}

// TestNoNewAnchorChangeRequested locks the gate around the funding check.
// skip_funding, add=true, and an existing change output must not run it.
func TestNoNewAnchorChangeRequested(t *testing.T) {
	t.Parallel()

	add := func(v bool) *wrpc.CommitVirtualPsbtsRequest {
		return &wrpc.CommitVirtualPsbtsRequest{
			AnchorChangeOutput: &wrpc.CommitVirtualPsbtsRequest_Add{
				Add: v,
			},
		}
	}

	existingIdx := &wrpc.CommitVirtualPsbtsRequest_ExistingOutputIndex{
		ExistingOutputIndex: 0,
	}
	existing := &wrpc.CommitVirtualPsbtsRequest{
		AnchorChangeOutput: existingIdx,
	}
	skipped := add(false)
	skipped.SkipFunding = true

	require.True(t, noNewAnchorChangeRequested(add(false)))
	require.False(t, noNewAnchorChangeRequested(add(true)))
	require.False(t, noNewAnchorChangeRequested(skipped))
	require.False(t, noNewAnchorChangeRequested(existing))
	require.False(t, noNewAnchorChangeRequested(
		&wrpc.CommitVirtualPsbtsRequest{},
	))
}

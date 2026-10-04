package commands

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/urfave/cli"
)

// finalizeBatchCLIContext builds a CLI context for the finalize command flags.
func finalizeBatchCLIContext(t *testing.T, args []string) *cli.Context {
	t.Helper()

	app := cli.NewApp()
	set := flag.NewFlagSet("finalize", flag.ContinueOnError)
	for _, cmdFlag := range finalizeBatchCommand.Flags {
		cmdFlag.Apply(set)
	}
	require.NoError(t, set.Parse(args))

	return cli.NewContext(app, set, nil)
}

// TestFinalizeBatchRejectsEmptySignedPsbtFile ensures a zero-length
// --signed_psbt file is rejected before a finalize request is built.
// os.ReadFile succeeds on that file, and FinalizeBatch treats an empty
// signed_psbt as wallet finalization.
func TestFinalizeBatchRejectsEmptySignedPsbtFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "signed.psbt")
	require.NoError(t, os.WriteFile(path, []byte{}, 0o600))

	ctx := finalizeBatchCLIContext(t, []string{
		"--" + signedPsbtName, path,
	})
	req, err := finalizeBatchRequest(ctx)
	summary := "<nil>"
	if req != nil {
		summary = fmt.Sprintf(
			"signed_len=%d fee_rate=%d", len(req.SignedPsbt),
			req.FeeRate,
		)
	}
	require.Error(
		t, err, "accepted empty --%s file: %s", signedPsbtName,
		summary,
	)
	require.Nil(t, req)
	require.ErrorContains(t, err, "empty")
	require.ErrorContains(t, err, "--"+signedPsbtName)
}

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

// fundBatchCLIContext builds a CLI context for the fund command flags.
func fundBatchCLIContext(t *testing.T, args []string) *cli.Context {
	t.Helper()

	app := cli.NewApp()
	set := flag.NewFlagSet("fund", flag.ContinueOnError)
	for _, cmdFlag := range fundBatchCommand.Flags {
		cmdFlag.Apply(set)
	}
	require.NoError(t, set.Parse(args))

	return cli.NewContext(app, set, nil)
}

// TestFundBatchRejectsCustomAnchorFlagsWithoutPsbt ensures custom-anchor
// output controls cannot be dropped when --anchor_psbt is omitted. Dropping
// them builds a normal wallet funding request.
func TestFundBatchRejectsCustomAnchorFlagsWithoutPsbt(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "no change output",
			args: []string{"--" + noChangeOutputName},
			want: "--" + noChangeOutputName,
		},
		{
			name: "pre commit output index",
			args: []string{
				"--" + preCommitOutputIndexName + "=0",
			},
			want: "--" + preCommitOutputIndexName,
		},
		{
			name: "asset anchor output index",
			args: []string{
				"--" + assetAnchorOutputIndexName + "=1",
			},
			want: "--" + assetAnchorOutputIndexName,
		},
		{
			name: "change output index",
			args: []string{"--" + changeOutputIndexName + "=1"},
			want: "--" + changeOutputIndexName,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := fundBatchCLIContext(t, tc.args)
			req, err := fundBatchRequest(ctx)
			summary := "<nil>"
			if req != nil {
				summary = fmt.Sprintf(
					"anchor_len=%d no_change=%v "+
						"pre_commit_set=%v "+
						"asset_idx=%d change_idx=%d",
					len(req.AnchorPsbt),
					req.NoChangeOutput,
					req.PreCommitOutputIndex != nil,
					req.AssetAnchorOutputIndex,
					req.ChangeOutputIndex,
				)
			}
			require.Error(
				t, err, "accepted fund without --%s: %s",
				anchorPsbtName, summary,
			)
			require.Nil(t, req)
			require.ErrorContains(t, err, tc.want)
			require.ErrorContains(t, err, "--"+anchorPsbtName)
		})
	}

	t.Run("wallet fund unchanged", func(t *testing.T) {
		t.Parallel()

		req, err := fundBatchRequest(fundBatchCLIContext(t, nil))
		require.NoError(t, err)
		require.Empty(t, req.AnchorPsbt)
		require.False(t, req.NoChangeOutput)
		require.Nil(t, req.PreCommitOutputIndex)
		require.Zero(t, req.AssetAnchorOutputIndex)
		require.Zero(t, req.ChangeOutputIndex)
	})

	t.Run("flags applied with anchor psbt", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "anchor.psbt")
		require.NoError(t, os.WriteFile(
			path, []byte{0x70, 0x73, 0x62, 0x74}, 0o600,
		))

		ctx := fundBatchCLIContext(t, []string{
			"--" + anchorPsbtName, path,
			"--" + noChangeOutputName,
			"--" + preCommitOutputIndexName + "=0",
			"--" + assetAnchorOutputIndexName + "=1",
		})
		req, err := fundBatchRequest(ctx)
		require.NoError(t, err)
		require.Equal(t, []byte{0x70, 0x73, 0x62, 0x74}, req.AnchorPsbt)
		require.True(t, req.NoChangeOutput)
		require.NotNil(t, req.PreCommitOutputIndex)
		require.Zero(t, req.GetPreCommitOutputIndex())
		require.EqualValues(t, 1, req.AssetAnchorOutputIndex)
	})
}

// TestFundBatchRejectsEmptyAnchorPsbtFile ensures a zero-length
// --anchor_psbt file is rejected before a funding request is built.
// os.ReadFile succeeds on that file, and FundBatch treats an empty
// anchor_psbt as wallet funding.
func TestFundBatchRejectsEmptyAnchorPsbtFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "anchor.psbt")
	require.NoError(t, os.WriteFile(path, []byte{}, 0o600))

	ctx := fundBatchCLIContext(t, []string{
		"--" + anchorPsbtName, path,
	})
	req, err := fundBatchRequest(ctx)
	summary := "<nil>"
	if req != nil {
		summary = fmt.Sprintf(
			"anchor_len=%d no_change=%v pre_commit_set=%v "+
				"asset_idx=%d change_idx=%d",
			len(req.AnchorPsbt), req.NoChangeOutput,
			req.PreCommitOutputIndex != nil,
			req.AssetAnchorOutputIndex, req.ChangeOutputIndex,
		)
	}
	require.Error(
		t, err, "accepted empty --%s file: %s", anchorPsbtName,
		summary,
	)
	require.Nil(t, req)
	require.ErrorContains(t, err, "empty")
	require.ErrorContains(t, err, "--"+anchorPsbtName)
}

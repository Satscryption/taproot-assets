package tapcfg

import (
	"testing"

	"github.com/btcsuite/btclog/v2"
	"github.com/stretchr/testify/require"
)

func TestValidateSupplyIdleCommitInterval(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()
	cfg.Universe.SupplyIdleCommitInterval = 0
	_, err := ValidateConfig(cfg, btclog.Disabled)
	require.NoError(t, err)

	cfg.Universe.SupplyIdleCommitInterval = MinSupplyIdleCommitInterval
	_, err = ValidateConfig(cfg, btclog.Disabled)
	require.NoError(t, err)
}

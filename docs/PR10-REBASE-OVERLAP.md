# PR #10 rebase overlap (planned stack)

PR #10 (`satscrip/v0.8.5-candidate`) is intended as **layer 3** atop:

1. `satscrip/v0.8.5-supplycommit-base` (stock v0.8.5)
2. `satscrip/supplycommit-anchor-fix` — `genesis_points.anchor_tx_id` / transfer-proof anchor retarget
3. `satscrip/supplycommit-burn-provenance` — upstream #2331 burn provenance

**Do not rebase #10 onto that stack yet.** This file lists touch points to reconcile during a later rebase.

## `genesis_points` / `AnchorGenesisPoint` / `upsertAssetGen`

| Area | #10 involvement |
|------|-----------------|
| `tapdb/universe.go` | `upsertAssetGen`, `AnchorGenesisPoint` on universe leaf insert (existing v0.8.5 path; unchanged by custom-anchor mint) |
| `tapdb/asset_minting.go` | `AnchorGenesisPoint` when committing mint batches to DB |
| Custom-anchor mint | Uses same `CommitMintingBatch` / genesis outpoint persistence as stock mint; anchor **output index** stored via `FundedMintAnchorPsbt.AssetAnchorOutIdx` and caretaker `anchorOutputIndex` |

**Conflict risk with anchor-fix branch:** any change to when/how `anchor_tx_id` is written on transfer must stay consistent with custom-anchor genesis outpoint selection (non-zero `asset_anchor_output_index`).

## Mint pre-commitment outputs

| Area | #10 involvement |
|------|-----------------|
| `tapgarden/planter.go` | `PreCommitOutputIndex`, `sealBatchPreCommit`, `fetchPreCommitGroupKey`, `PreCommitTxOut` in custom `customGenesisPsbt` |
| `tapgarden/custom_anchor.go` | Validates pre-commit output index vs delegation key for supply-commitment batches |
| `rpcserver` / `mintrpc` | `FundBatchRequest.pre_commit_output_index` |

**Overlap:** supply-commit stack may alter pre-commit / genesis anchoring semantics; rebase must re-run `custom_anchor_test.go` supply pre-commit cases and supply itests.

## Supply-commit FSM (`universe/supplycommit`)

| Area | #10 involvement |
|------|-----------------|
| `conf_finalize.go` | Burial-gated finalize (shared with recovery); not full `tapreorg` |
| `broadcast_recovery.go` | Scan + buried-only recovery |
| `transitions.go` | `RegisterConf` uses `commitBurialDepth`; `ConfEvent` → `transitionForBuriedConf` |
| `manager.go` | `CommitFinalizeState` resume via `FinalizeEvent`; broadcast resume comment |
| `itest/supply_commit_test.go` | `MineSupplyCommitBurial`, idle interval vs burial depth |
| `itest/assertions.go` | `UpdateAndMineSupplyCommit` + burial helper |

**Overlap:** anchor-fix and burn-provenance branches may change commitment creation, proof binding, or FSM inputs; burial/recovery paths must be merged with any upstream `tapreorg` work on the stack.

## Migrations

Fork migrations **000073** / **000074** (custom anchor PSBT) **collide in number** with upstream `main` if ever upstreamed — noted in PR #10 body.

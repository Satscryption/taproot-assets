# PR #10 review fix — paused status

**Branch:** `satscrip/v0.8.5-candidate`  
**Paused:** 2026-10-09 (user-ordered stop)  
**Reference:** lightninglabs/taproot-assets#2238 (`0aa23214`)  
**Prior head before this WIP:** `eba5bb53`

## Validation at pause (not complete)

| Check | Status |
|-------|--------|
| `make unit` (full repo) | **Not re-verified green** after last planter/itest edits; `tapgarden`, `universe/supplycommit`, `universe/supplyverifier` were green individually before late planter changes |
| Targeted itests | **Mixed / failing** — see below |
| `make itest-parallel` | **Was running in tmux; stopped on pause** — not confirmed green on this WIP |
| `tapd-itest` SHA256 | **Not recorded** for this WIP |
| PR #10 body update | **Not done** (migration 73/74 note, mint_batch_resume story) |

### Targeted itest notes (last runs before pause)

- `mint_batch_resume` — **PASS** (earlier run on this WIP)
- `mint_custom_anchor_psbt` — not re-run after all fixes; passed on older harness before harness revert
- `mint_custom_anchor_psbt_restart` — **FAIL** on second `FinalizeBatch` (`no pending batch`) until late gardener idempotent fix; **not re-run after that fix**
- `supply_commit_idle_tick` — **FAIL** (idle successor / mempool timing; interval bumped to 12 + burial mining helpers added; **not re-run after final planter edits**)

---

## Blocking items (6)

### 1. Revert itest data-dir deferral; `stop(false)` for restart tests

| Status | **Done** |
|--------|----------|
| Work | Removed `pendingDataDeletion` / `purgeDataDir` from `itest/tapd_harness.go` and `itest/test_harness.go`. `itest/supply_commit_test.go` uses `stop(false)` for idle-tick restarts. |
| Verify | Idle-tick itest still failing for other reasons (item 2 / burial); harness revert itself is in tree. |

### 2. `broadcast_recovery.go` / supply commit burial & resume

| Status | **Mostly done** — unit tests added; **not** full upstream `tapreorg` port |
|--------|-----------------------------------------------------------------------------|
| Done | `conf_finalize.go`: burial depth, `isCommitBuried`, shared `applyConfToTransition` / `transitionToCommitFinalize` / `transitionForBuriedConf`. Recovery only finalizes when buried; scan RPC errors propagate. `manager.go`: `CommitFinalizeState` resumes via `FinalizeEvent`; broadcast-state comment fixed. `transitions.go`: conf registration uses burial depth; recovery on broadcast/tick. Tests: `broadcast_recovery_test.go`, `TestCommitFinalizeStateResumeFinalizeEvent`, mock `GetBlockByHeight` expectations. |
| Partly | `BroadcastEvent` / tick handlers still use `context.Background()` in places (not caller `ctx`). No dedicated unit test for **reorg-out before burial** (only not-buried recovery + scan error). |
| Not started | Full `tapreorg` watcher integration as on upstream main. |

### 3. Prepared custom-anchor batch: no wallet sign on restart

| Status | **Mostly done** |
|--------|-----------------|
| Done | `caretaker.go`: custom anchor stays in `BatchStateCommitted` if PSBT not extractable; no `SignAndFinalizePsbt` on restart. `prepareBatch` persists `BatchStateCommitted`. `planter.go`: skip caretaker for unsigned custom anchor; `attachPendingCustomAnchorBatch` on start/finalize; lease renew on prepare/finalize and on restart while awaiting sig. |
| Partly | Idempotent **second `FinalizeBatch`** after broadcast — gardener/caretaker logic added late; **not itest-verified**. Signed packet persistence before publish via existing `CommitSignedGenesisTx` path — not separately audited vs #2238. |

### 4. Confirmation watches asset anchor output index

| Status | **Done** |
|--------|----------|
| Work | `caretaker.go` `BatchStateBroadcast`: `RegisterConfirmationsNtfn` uses `signedTx.TxOut[anchorIdx].PkScript` with `b.anchorOutputIndex`. |

### 5. Refuse cancel after prepare (#2238)

| Status | **Done** (code) — **no itest** |
|--------|--------------------------------|
| Work | `planter.go` `cancelMintingBatch`: error for prepared custom anchor in `BatchStateCommitted`. |

### 6. `TestVerifyBurnLeaf` negatives + empty proof file

| Status | **Done** |
|--------|----------|
| Work | `universe/supplyverifier/verifier.go`: `checkBurnLeafInputs` rejects `inputFile.IsEmpty()` → `"empty proof file"`. `verifier_methods_test.go`: bare suffix / duplicate / empty subtests restored. `make unit pkg=universe/supplyverifier` passed before pause. |

---

## Non-blocking items

| Item | Status |
|------|--------|
| SIGHASH_ALL/DEFAULT before irreversible | **Done** — `validateAnchorInputSigHashTypes` in `validateFinalizedAnchorPsbt`; unit tests in `custom_anchor_test.go` |
| Min relay fee before irreversible | **Done** — `validateCustomAnchorFeeRate` on `FinalizeBatch` signed PSBT path |
| Every wallet-owned input locked | **Mostly done** — post-lease check in `lndservices/wallet_anchor.go` `LeaseInputs`; no dedicated unit test |
| Renew lease through signing pause | **Mostly done** — `renewCustomAnchorLeases` on prepare, finalize, and restart while awaiting external sig; no long-pause itest |
| Real change index + copy caller PSBT | **Done** — `customGenesisPsbt` copies packet; `ChangeOutIdx` from `changeOutputIndex`; validate before copy |
| PR note: migrations 000073/000074 vs upstream main | **Not started** (PR body not updated) |
| Unit tests: non-local anchor key, sighash, below-relay fee, restart prepared, cancel after prepare, non-zero anchor, second finalize | **Partly done** — sighash + PSBT copy tests; cancel/restart/fee/non-local anchor **not** fully covered in unit tests |
| itest: restart-while-prepared + non-zero anchor index | **Partly done** — `testMintCustomAnchorPsbtRestart` added (anchor index 1, restart, double finalize); **failing / not green** at pause |
| `make unit` + full itest matrix | **Not complete** at pause |

---

## Next steps when resuming

1. Re-run `make unit`, then targeted itests (`mint_custom_anchor_psbt`, `mint_custom_anchor_psbt_restart`, `mint_batch_resume`, `supply_commit_idle_tick`), then `make itest-parallel`.
2. Confirm `mint_custom_anchor_psbt_restart` and `supply_commit_idle_tick` after latest `planter.go` / idle-interval / burial-mining changes.
3. Add reorg-before-burial unit test; optionally replace `context.Background()` in supply-commit FSM handlers where env provides ctx.
4. Update PR #10 body (migration collision, honest `mint_batch_resume` / `b3ccda36` story, per-item table).
5. Commit message prefix per repo convention; sign commit if required locally.

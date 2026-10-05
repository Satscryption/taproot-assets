-- finished_at is when a CommitVirtualPsbts request recorded a terminal
-- outcome (completed or failed). Pending rows leave it null and are
-- never purged. The partial index lets retention delete old responses
-- without reading the record blob, which can be up to 32 MiB.
-- Existing rows stay null; no backfill is required.

ALTER TABLE commit_virtual_psbt_idem
    ADD COLUMN finished_at TIMESTAMP;

CREATE INDEX commit_virtual_psbt_idem_finished_at_idx
    ON commit_virtual_psbt_idem (finished_at)
    WHERE finished_at IS NOT NULL;

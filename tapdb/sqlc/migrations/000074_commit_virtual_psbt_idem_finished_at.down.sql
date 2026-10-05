DROP INDEX IF EXISTS commit_virtual_psbt_idem_finished_at_idx;

ALTER TABLE commit_virtual_psbt_idem
    DROP COLUMN finished_at;

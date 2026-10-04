-- commit_virtual_psbt_idem stores the outcome of CommitVirtualPsbts
-- calls that set a request_id. The record blob is an opaque encoding
-- owned by the RPC server, so later fields do not need a migration.
CREATE TABLE IF NOT EXISTS commit_virtual_psbt_idem (
    -- request_id is the caller-supplied idempotency key.
    request_id BLOB PRIMARY KEY
        CHECK (length(request_id) BETWEEN 1 AND 64),

    -- record holds the pending or completed commit outcome.
    record BLOB NOT NULL
);

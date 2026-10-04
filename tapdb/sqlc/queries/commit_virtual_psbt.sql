-- name: InsertCommitVirtualPsbt :exec
INSERT INTO commit_virtual_psbt_idem (
    request_id, record
) VALUES (
    $1, $2
);

-- name: FetchCommitVirtualPsbt :one
SELECT record
FROM commit_virtual_psbt_idem
WHERE request_id = $1;

-- name: UpdateCommitVirtualPsbt :execrows
UPDATE commit_virtual_psbt_idem
SET record = $2
WHERE request_id = $1;

-- name: DeleteCommitVirtualPsbt :exec
DELETE FROM commit_virtual_psbt_idem
WHERE request_id = $1;

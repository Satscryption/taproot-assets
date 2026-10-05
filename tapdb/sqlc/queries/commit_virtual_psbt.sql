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

-- name: ListCommitVirtualPsbts :many
SELECT request_id, record
FROM commit_virtual_psbt_idem;

-- name: UpdateCommitVirtualPsbt :execrows
UPDATE commit_virtual_psbt_idem
SET record = $2
WHERE request_id = $1;

-- name: DeleteCommitVirtualPsbt :exec
DELETE FROM commit_virtual_psbt_idem
WHERE request_id = $1;

-- name: SwapCommitVirtualPsbt :execrows
UPDATE commit_virtual_psbt_idem
SET record = sqlc.arg('next_record'),
    finished_at = COALESCE(sqlc.narg('finished_at'), finished_at)
WHERE request_id = sqlc.arg('request_id')
  AND record = sqlc.arg('expected_record');

-- name: PurgeFinishedCommitVirtualPsbts :execrows
DELETE FROM commit_virtual_psbt_idem
WHERE finished_at IS NOT NULL
  AND finished_at < sqlc.arg('finished_before');

-- name: ListFinishedCommitVirtualPsbtsBefore :many
SELECT request_id, record
FROM commit_virtual_psbt_idem
WHERE finished_at IS NOT NULL
  AND finished_at < sqlc.arg('finished_before');

-- name: ListUnstampedCommitVirtualPsbts :many
SELECT request_id, record
FROM commit_virtual_psbt_idem
WHERE finished_at IS NULL;

-- name: DeleteCommitVirtualPsbtIf :execrows
DELETE FROM commit_virtual_psbt_idem
WHERE request_id = sqlc.arg('request_id')
  AND record = sqlc.arg('expected_record');

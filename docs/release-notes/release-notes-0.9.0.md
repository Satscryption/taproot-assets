# Release Notes

## RPC Updates

- `PublishAndLogTransfer` and related publish paths document that
  `request_id` deduplication is **process-local and in-flight only**:
  it is released when the publish attempt finishes and is not retained
  across daemon restarts.

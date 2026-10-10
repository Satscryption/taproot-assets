# Release Notes
- [Bug Fixes](#bug-fixes)

# Bug Fixes

* [PR#2317](https://github.com/lightninglabs/taproot-assets/pull/2317)
  updates RFQ quote accounting to track settled amounts separately from
  pending HTLC reservations and restore settled usage from forwarding records
  on startup. Failed HTLCs continue to release their reservations.

* [PR#2319](https://github.com/lightninglabs/taproot-assets/pull/2319)
  makes the encoding of proofs canonical. The STXO proofs within a proof, and
  the outputs of a send fragment, were encoded in the random iteration
  order of a map, so encoding the same proof twice could yield different
  bytes. A supply commitment verifier re-encodes burn proofs to compute
  their universe leaves, and could reject a supply commitment for a burned
  asset that spent several inputs. Both are now encoded sorted by key.

* [Universe servers no longer reject supply commitments that carry
  burns](https://github.com/lightninglabs/taproot-assets/pull/2331).
  A burn leaf's proof is a bare state transition, with no provenance
  for the input it consumes, and was verified as if it were
  self-contained, so every such commitment failed with `missing asset
  input(s)` and the group stopped publishing supply commitments. The
  verifier now checks the burn against its input's provenance: a
  universe server takes it from its own universe, and a node syncing
  supply commitments from the servers it pulls from. The issuer
  publishes that provenance to each server before pushing the
  commitment.

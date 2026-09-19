## colibri-review: the scan ladder is standing law (owner order 2026-09-19)

- Gate CLEAR ≠ reviewed: after any feature run, EVERY changed file (tests
  included) gets a full-file bug scan by a model family outside the gate
  chain (default hy4-preview) — disclose the batch cost first.
- Any HIGH/CRITICAL escalates to a THIRD model (default grok-4.6, effort
  high) with the prior scan as context, hunting NEW findings only.
- All findings adversarially verified before they count; confirmed defects
  remediated + logged the same session; every pass recorded as manifest
  pass lineage (counts toward the three-model lock).
- New test files are first-class: the gate takes them on commit, the M2
  scan after the run.
- Full protocol: the colibri-review skill, section "The scan ladder".

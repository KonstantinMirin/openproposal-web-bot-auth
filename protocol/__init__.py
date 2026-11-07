"""STOPGAP: the OpenProposal rules both parties run that the generated SDK doesn't emit yet.

The types come from the generated SDK, `openproposal` (vendor/openproposal-sdk),
and callers import them from there. This package holds only what the generator
doesn't emit yet, typed on the generated classes:

- the § 4.1.1 binding record, digest input, and `record_digest`, and the § 3.4
  buyer writes they compose over (`protocol.record`);
- the § 4.1.1 YAML core-schema reading (`protocol.documents`);
- the § 4.1.2 attribution rule and pair rule (`protocol.attribution`,
  `protocol.values.matches`);
- the § 5.6.1 `commit` rules the generated `Commit` and `CommitResult` don't state,
  and the buyer's and the seller's steps over them (`protocol.operations`).

When the schema tooling emits these helpers (wbademo-uo9, "Ask the schema
tooling to emit the binding-record and record_digest helper"), both parties
import them from the generated package and this package is deleted.

Nothing here does I/O, reads configuration, or knows a framework.
"""

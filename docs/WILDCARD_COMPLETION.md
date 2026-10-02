# Wildcard assessment completion

A wildcard scan enumerates hosts and then assesses the admitted inventory.
Finishing enumeration or terminating every child is not proof of complete
assessment coverage.

The parent `status` and `sub_scan_completed` describe lifecycle. A child that
ends with a partial assessment still counts as a terminated child. Findings,
original start times, usage, and the child's own outcome are retained.

The parent's `completion` describes the assessments:

- While pending or running, no terminal completion label is returned.
- `full` requires a normally completed parent, successful enumeration, a
  nonempty inventory, and a known full outcome for every physical child.
  Known unfinished plan tasks prevent a full result.
- `partial` includes partial, failed, stopped, unstarted, or unknown children;
  unknown enumeration results; missing inventory entries; and resource caps.
  A legacy `finished` child without completion metadata is unknown coverage.

`discovery` retains the enumeration session's separate outcome, plan, clocks,
and usage. It is not included in `sub_scans` or assessment plan totals.
Each `sub_scans` entry carries the physical child's `completion`, `stop_reason`,
and saved plan dispositions when available. Event descriptors and sibling
records do not supply those facts.

Parent `plan_tasks_total`, `plan_tasks_completed`, `plan_tasks_skipped`, and
`plan_tasks_unfinished` sum child plans only when every inventory child has a
known, internally consistent plan. Otherwise aggregate plan counters are
omitted; individual known child plans remain available. Known zero counts are
serialized as zero. Skipped tasks remain distinct from executed coverage,
even when a child resolves its obligations and reports `full`.

`sub_scan_skipped` counts discovered candidates omitted by an explicit resource
cap. Mandatory targets and previously started physical children survive a
smaller cap on resume. A persisted omitted-candidate count continues to prevent
a full claim after restart.

Aggregate stop reasons are `wildcard_assessment_incomplete`,
`wildcard_assessment_unknown`, `wildcard_discovery_incomplete`, or
`wildcard_resource_limit`. An explicit coordinator cancellation or failure
reason takes precedence. Child reasons stay on their own records and summaries.

Recovery rebuilds assessment metadata from owned physical child records and
preserves independent child evidence. Existing lifecycle, cancellation,
execution, findings, and billing guards are unchanged.

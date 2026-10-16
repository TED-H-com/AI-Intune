# Repository guidance

For fleet AI CLIs, follow [skills/fleet-ai-cli/SKILL.md](skills/fleet-ai-cli/SKILL.md).
For Fly deployments, follow [skills/clawctl-fly-deploy/SKILL.md](skills/clawctl-fly-deploy/SKILL.md).
For local timer summaries and daily host checks, follow [skills/fleet-daily-check/SKILL.md](skills/fleet-daily-check/SKILL.md).
For Oracle Cloud VM deployments, follow [skills/clawctl-oci-deploy/SKILL.md](skills/clawctl-oci-deploy/SKILL.md).
For new host bootstrap and network checks, follow [skills/fleet-host-bootstrap/SKILL.md](skills/fleet-host-bootstrap/SKILL.md).
For operating an existing Hub, follow [skills/clawctl-operator/SKILL.md](skills/clawctl-operator/SKILL.md).

For host migration and generic deploys, follow [skills/fleet-host-migration/SKILL.md](skills/fleet-host-migration/SKILL.md).
For tool removal, follow [skills/fleet-tool-removal/SKILL.md](skills/fleet-tool-removal/SKILL.md).

Do not merge PRs unless the human asked. Do not print secrets.

## Interface copy

- Every Web, CLI, installer, and API message contains only the current state, available action, concrete impact, and exact next step.
- Never expose development history, implementation gaps, temporary guards, migration commentary, defensive explanations, responsibility disclaimers, or speculative caveats in the product interface.
- Represent unavailable data as a concise typed state. Do not explain the implementation behind it.
- Show only actions the authenticated operator can use. Do not replace unavailable actions with disabled controls or capability lectures.
- Keep confirmations focused on target, effect, and required confirmation. Keep protocol evidence in structured receipts and audit records.
- Do not expose placeholders, partial workflows, or temporary navigation. Finish the vertical slice before making it visible.
- Put legal terms in the dedicated terms surface linked from installation or the final page, never inline with the task flow.
- Tests must cover concise interface copy and prevent banned implementation language from returning. `forbiddenInterfaceCopy` in `internal/web/interface_copy_test.go` scans templates and production Go strings; extend it instead of loosening it.

## Delivery

- Complete each workflow across Web, CLI, API, persistence, audit, tests, documentation, and deployment before starting the next visible workflow.
- Remove replaced paths and unused compatibility helpers when canonicalizing a workflow.

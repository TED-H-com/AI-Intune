# List and navigation review

Reviewed against public source revision `4b0db8a`. This review covers the rendered
operator navigation, device lists, registration lifecycle and the adjacent
application, activity, report and tenant lists. It is a source and synthetic
fixture review; production registry entries require a separate authenticated
inventory read before disposition.

## Canonical locations

| Workload | Primary lists and actions | Distinction |
| --- | --- | --- |
| Dashboard | Fleet state and activity summary | Links to the canonical rosters; retired rows are not repeated here |
| Devices | Active roster, retired roster, registry cleanup, enrollment and waiting-to-join, configuration, compliance, agent updates | Current inventory, historical registrations and cleanup review have separate views |
| Agents | Job activity, CLI sign-ins, attention/loop episodes | Runtime operations and their evidence |
| Apps | Catalog, profiles, assignments, artifacts/fetch, deployments | A package, a composed profile, a target assignment and a deployment are different records |
| Endpoint security | Tailnet and authorized credential administration | Access and credential controls |
| Reports | Checks, changes, tickets, enrollment, software, install, profile and audit reports | Read/export evidence, rather than another place to mutate configuration |
| Tenant administration | Notification channels, offline alerts, schedules, maintenance, disk policy/approval/alerts, certificates and data retention | Fleet-wide settings and their pending decisions |
| Troubleshooting | Device diagnostics and readiness | Readiness evidence and diagnostic actions |

`/channels` configures notification/chat connections. It is distinct from the
canary/stable software update channels on `/updates` and device detail pages.

## Corrected list behavior

- `/machines` starts with active registry entries. Explicit `lifecycle=any`
  supports historical searches; `lifecycle=retired` is the history view.
- The device overview, roster and monitoring tabs render their selected content.
  The roster is no longer below a second dashboard, especially on phones.
- Device IDs remain visible when names repeat. Technical filters are grouped in
  an expandable section which opens when those filters are applied.
- Registry cleanup replaces the second all-device lifecycle table with candidate
  evidence and links to the existing lifecycle review on device detail pages.
- Navigation shares one definition per workload. Moved links retain their routes
  and authorization checks; contextual links still connect related workflows.

## Registration and history rules

A matching display name or hostname is evidence to compare, not a unique device
identity. A previously enrolled or previously reporting device is never selected
by the existing stale-registration rule. An offline laptop, a rebuilt host and
an abandoned ticket require different decisions.

The existing store rule selects only non-retired entries with no enrollment and
no check-ins, created at least one hour ago, with no live enrollment ticket or
pending unexpired join request. They must also either match a reporting entry by
name/hostname or have remained unused for at least 24 hours. The Web, read API and
operator CLI/MCP expose that same evidence. Reading candidates changes no state.

Retirement still requires the canonical preview, exact display-name confirmation,
revision, reason and matching preview digest. It preserves history and audit
records and changes the device's authentication/lifecycle state. Restoration uses
the same reviewed lifecycle path. Nothing in the list review deletes registrations
or merges identities automatically.

## Production inventory reconciliation

Use an authenticated `fleet_overview`, then page `machines_list` until complete.
For repeated names, compare device IDs, enrollment dates, last Hub-received
check-in/observation, identity hints and the actual replacement relationship.
Separate these dispositions:

1. Active devices: retain; fix naming only after identity is established.
2. Unused registrations meeting the stale rule: inspect each candidate and its
   related device, then use the existing lifecycle preview/confirmation.
3. Previously reporting old registrations: establish the replacement or retirement
   decision individually; age and a matching name are insufficient.
4. Retired history: keep in the history view. Permanent data deletion is a separate
   explicit operation with its own preview and retention rules.

Record the before/after counts, target IDs and lifecycle/audit receipts in a private
operations record. Public repository documentation must not contain fleet IDs,
hostnames, credentials or production exports.

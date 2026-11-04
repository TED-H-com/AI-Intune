# AI-Intune interface

## Visual theme and atmosphere

A compact operator console. Preserve the existing neutral shell, two levels of
navigation, blue links and dense tables. Names, states and the next available
action lead; protocol fields belong in details and receipts. The existing device
list and `internal/web/templates/base.html` are the visual reference.

## Color palette and roles

Reuse CSS variables in `base.html`: canvas `--canvas` (#faf9f8), surface
`--surface` (#fff), secondary surface `--surface-alt` (#f7f7f7), sidebar
`--sidebar` (#f3f2f1), text `--ink` (#201f1e), secondary text `--dim` (#605e5c),
borders `--line` (#e1dfdd) and `--line-strong` (#c8c6c4), action `--accent`
(#006fc9). State colors are `--green` (#107c10), `--amber` (#ca5010) and
`--red` (#a4262c). State text accompanies color.

## Typography

Use the existing system stack with Segoe UI, Noto Sans TC, PingFang TC and
Microsoft JhengHei fallbacks. Body is 14px / 1.5; `.small` is for secondary
metadata. Names and actions use semibold. `.mono` is for identifiers. Never
compress long identifiers by removing the distinctions between registrations.

## Components

Use `.panel`, `.section-title`, `.button`, `.button.secondary`, `.st` and shared
table styles. One primary action per form; navigation links remain links. Put
advanced filters in a native `details` element, open while any are applied.
Forms have explicit labels and visible keyboard focus. Tables scroll inside an
accessible labelled region; page content must not force horizontal overflow.
Unavailable data has a concise typed state. Only render authorized actions.

## Layout

The desktop shell uses existing 48px topbar, 212px sidebar and 224px workload
rail. Match existing spacing: 6px inline padding, 10–14px control gaps and
18px section separation. Keep the existing 2px control radius. Show the selected
workload view directly; do not put a second dashboard before a device table.

## Depth

Keep `--shadow` (0 1px 3px rgba(0,0,0,.12)) for existing surfaces. No new floating
cards, gradients or decorative effects for registry lists.

## Do and do not

- Give each workflow one primary workload location; contextual links can cross
  workloads when they support a specific task.
- Separate active devices, retired history and registry cleanup review.
- Retain device IDs when names repeat; names are not unique identities.
- Put evidence and the canonical reviewed action together. No automatic merges
  or retirement based only on a matching name or a stale heartbeat.
- Keep raw revisions, query consistency terms and development explanations out
  of list copy. Preserve them in API contracts and structured receipts.

## Responsive behavior

Retain existing 1100px, 760px and 430px breakpoints. At 760px the navigation rails
become horizontal; compact filters wrap. Touch controls and pagination links
in roster views have at least 44px targets. Inspect 390, 768 and 1440px widths.

## Agent prompt guide

Use existing tokens and classes before adding narrowly scoped styles.

- A list shows identity, status and recent evidence; advanced filters stay
  collapsed unless applied.
- A cleanup page shows candidate evidence and a link to the existing reviewed
  lifecycle action; history remains available in the retired roster.
- A detail page groups evidence for one device and keeps confirmation adjacent
  to its concrete effect.

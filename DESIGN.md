# AI-Intune interface system

## Direction

The admin center follows [the Intune reference contract](docs/INTUNE-UI-REFERENCE.md):
a dark product bar, neutral workload rails and compact evidence tables. Preserve
status meaning, permissions, review steps and audit behavior when changing layout.
The public `site/` landing page has its own marketing layout.

## Source of truth

`internal/web/templates/styles.html` owns shared styles and tokens. `base.html`
owns the authenticated shell. `account-layout.html` uses the same styles for sign-in,
setup, MFA and account management; standalone Go templates use `web.NewAccountTemplate`.
Styles are embedded in the binary and work with the existing inline-style CSP.

## Color and type

Reuse the existing neutral palette: `--topbar` #323130, `--canvas` #faf9f8,
`--surface` #fff, `--ink` #201f1e, `--dim` #605e5c and `--line` #e1dfdd.
`--accent` #006fc9 is for links, selected navigation and primary actions.
Green, amber and red indicate status only; always include a text label.

Use `--font-ui` (system UI with Traditional Chinese fallbacks), 14px body with
1.6 line height, 12–13px metadata, 18px section headings and 28px page titles.
Reserve 32px tabular numerals for summary counts. Allow identifiers and evidence
to wrap; use monospace for protocol values, never as the general interface font.

## Components

- `.page-heading`: title, short description and `.command-bar` with one primary action.
- `.panel`: bounded evidence or form section. `.table-panel`: edge-aligned ledger.
- `.filter-panel`, `.filter-row`, `.filter-states`: labelled list filters, separate
  multi-select states, explicit submit and clear actions.
- `.button` / `button`: primary; `.secondary`: supporting action; `.danger`: destructive.
  Filter submission is outlined. Controls are 36px on desktop and 44px on mobile.
- `.disk-form`, `.enrollment-form`, `.action-form`: shared form patterns. Checkboxes
  and radios retain their intrinsic size. Actions do not stretch on desktop.
- `.empty`: concise empty state. Alerts retain a readable message and next action.
- `.table-scroll`: horizontally scrollable wide data within the page boundary.
  Give interactive tables a region label and keyboard focus with `tabindex="0"`.
- `.facts`: aligned definition lists for review and evidence pages; labels and values
  become stacked pairs on phones. Preserve full identifiers and long reasons.
- `.panel-stack`: consistent spacing between independent sections. `.row-actions`:
  compact related table actions. Do not introduce alternate card/KPI class names.

## Layout and elevation

Use the 4/8/12/16/24/32px spacing tokens, a 4px radius, and border-separated surfaces.
Panels and metrics have no shadow; the product bar supplies the main elevation.
The content region is capped at 1600px. The desktop rails are 196px and 188px.
Device lists put metrics, filters and rows before supporting overview evidence.

## Responsive behavior

At 1200px, use narrower rails and two-column summary tiles. At 1100px, the workload
rail becomes a horizontally scrollable row above the content. At 760px, the primary
rail becomes a scrollable row too, forms stack, and inputs use 16px text with 44px
controls. Keep two summary tiles per row on phones. Wide ledgers scroll inside
panels; the document must not overflow at 390, 768 or 1440px.

## Guardrails

Use the established templates before introducing new styles. Replace repeated
inline layout rules with shared classes. Avoid nested decorative cards, disabled
unavailable actions, fabricated metrics and implementation language in product copy.
Keep navigation localized; do not relabel untranslated evidence as English.
`navigationGroup` keeps detail/report/tenant pages selected in their parent workload.

## Review

Run the Web and Hub tests with a disk-backed `TMPDIR`. Export real rendered fixtures:

```sh
CLAWCTL_INTERFACE_PREVIEW_DIR=/path/on/disk go test ./internal/web -run '^TestInterface(Populated)?Preview$' -count=1
```

Open the exported HTML in a browser at 390, 768 and 1440px. Check populated and
empty lists, long identifiers, form focus, checkboxes, review flows and account pages.
Include populated sign-in sessions, administrator and viewer states, channel bindings,
and review confirmations. `TestDeepDiskScreenshotFixtures` exports disk reports with
`CLAWCTL_SCREENSHOT_DIR`; `TestAccountPagesShareResponsiveLayout` in `cmd/clawctl-hub`
exports account pages with `CLAWCTL_INTERFACE_PREVIEW_DIR`. Fixtures use an isolated
store and never access a running Hub.

## Applying the system

For a list, use heading → filters → table → pagination. For a detail page, use
heading → current state → evidence sections. For a review, show target, impact,
required confirmation and submit action. For account forms, reuse the account
layout, associated labels and existing credential autocomplete semantics.

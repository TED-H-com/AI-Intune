# P2-04 human disk actions

Production-template HTML fixtures use generic public data:

- `disk-report-viewer.html`: active per-item and bulk controls.
- `disk-action-confirm.html`: exact quarantine confirmation and fresh reauth.
- `disk-quarantine-list.html`: retained bytes, expiry countdown and restore.
- `disk-restore-preview.html`: original destinations and separate confirmation.

Generate with `bash ops/screenshots/phase2-disk-actions.sh`. PNG generation was
sandbox-blocked: Chromium's sandbox host cannot open its required socket
(`shutdown: Operation not permitted`). The HTML generation and escaping tests pass.

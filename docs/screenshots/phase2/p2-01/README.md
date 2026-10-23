# P2-01 human UI fixtures

Run `ops/screenshots/phase2-disk.sh` from this checkout to regenerate the six
server-rendered fixture pages and, when Chrome can start, matching PNGs.
The script uses generic fixture identities and the actual Hub templates. No
agent, notifier, network service, or real deployment data is required.

This environment has Chrome installed, but sandbox socket restrictions prevent
startup (`shutdown: Operation not permitted`). The fixture HTML is saved here;
open it directly in a browser or rerun the script in a browser-capable environment.

- `disk-policies.html`: revision list, canonical JSON/digest, typed editor.
- `disk-policy-preview.html`: before/after diff and reauthentication form.
- `disk-policy-removal-preview.html`: per-path Remove protection confirmations.
- `approvals.html`: all five ledger states, saved decision reasons and human-admin decision buttons.
- `approval-preview.html`: digest/deadline-bound decision and reauthentication.
- `disk-policies-disabled.html`: safe defaults and default-off state.

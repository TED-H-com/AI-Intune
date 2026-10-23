# Fleet AI CLIs

Run these tools as the main Linux user, for example `ops`. The standard is
Claude Code, Codex, Grok, and Google Antigravity CLI (`agy`). Gemini is legacy:
use agy. The installer reports no login success and never removes Gemini.

| CLI | Install | Login evidence |
| --- | --- | --- |
| claude | Global npm `@anthropic-ai/claude-code` | Automation wrapper and private OAuth token |
| codex | Global npm `@openai/codex` | `~/.codex/auth.json`, mode 600 |
| grok | `https://x.ai/cli/install.sh` | `~/.grok/auth.json`, mode 600 |
| agy | `https://antigravity.google/cli/install.sh` | `~/.gemini/antigravity-cli/antigravity-oauth-token` |

Grok installs to `~/.grok/bin/grok`. Link it from `~/.local/bin/grok`.
The installer links agy from known user install locations when present.
Existing Node.js is kept. If Node.js is missing, install Node.js 22 through
NodeSource. Package steps set `NEEDRESTART_MODE=l`. Never run `apt upgrade`.
Scripts never log in or restart services.

## Check and install

From a checkout on the host, as the target user:

```bash
bash ops/fleet/ai-cli/check-ai-clis.sh
bash ops/fleet/ai-cli/check-ai-clis.sh --json
bash ops/fleet/ai-cli/install-ai-clis.sh --plan
bash ops/fleet/ai-cli/install-ai-clis.sh --apply
# Optional subset:
bash ops/fleet/ai-cli/install-ai-clis.sh --apply --only claude,codex
```

Plan is the default and changes nothing. Apply runs user steps. Non-root apply
prints root steps as single-line `sudo bash -c '...'` commands. Review and run
those commands, then re-check. Do not run the entire installer with sudo unless
root is the intended CLI user. It uses the current HOME for all user steps.
Keep the installer beside `claude-automation`; copy the directory together.
Backups of existing config files use `.bak-<UTC stamp>`.

The PATH fix prepends `~/.local/bin` and `~/.grok/bin` to `/etc/environment`
for pam_env and to a marked block at the top of `~/.bashrc`, before its
interactive early return. It does not source either file. Open a new SSH session:

```bash
ssh host-a grok --version
```

The checker approximates noninteractive resolution: the binary directory must
be in `/etc/environment` PATH or be `/usr/bin` or `/usr/local/bin`. It cannot
prove that the SSH server enables pam_env. Verify with the SSH command above.
`--user-home DIR` selects credential and rc paths for inspection; it does not
switch users or change PATH.

## Human logins

For Claude, run `claude setup-token` interactively. Save the long-lived,
non-refreshing OAuth token privately to
`~/.config/claude-automation/oauth-token`. Use mode 600 or 400. The file must
belong to the user and must not be a symlink. Never put its value in a command,
rc file, report, or log. The installer creates only the directory, mode 700.

Automation always uses:

```bash
claude-automation -p 'Reply with exactly the word OK'
```

Never automate bare `claude -p` or `claude --print`. The wrapper sets
`CLAUDE_CODE_OAUTH_TOKEN` from the private file and clears alternate Anthropic
credentials and cloud-provider switches. This avoids rotating the interactive
login in `~/.claude/.credentials.json`. Interactive Claude may stay logged out.
`CLAUDE_AUTOMATION_TOKEN_FILE` can select another private file.
`CLAUDE_AUTOMATION_CLAUDE_BIN` can select the real Claude executable.
Otherwise the wrapper searches PATH and skips itself. Invalid token files or
missing Claude exit 78. Do not enable shell tracing around credentials.

For Codex, a human runs:

```bash
codex login --device-auth
codex login status
```

A privately copied `~/.codex/auth.json` with mode 600 is also supported.
Complete Grok and agy login interactively. Keep Grok auth mode 600.
No script performs login. Auth-file presence is evidence, not proof of a valid
session. The agy layout is reported as unknown when it cannot be detected.

```bash
bash ops/fleet/ai-cli/check-ai-clis.sh --live --json
agy -p 'Reply with exactly the word OK'
```

Live checks send one small prompt per CLI and may incur usage charges. Each has
a 30-second timeout. Claude runs only through the wrapper. Codex uses
`codex exec --skip-git-repo-check`; Grok and agy use `-p`. Results are `ok`,
`auth_fail`, or `error`. Raw prompt output is never printed. Version checks
have a 10-second timeout and retain only a version number.

The checker reports `ok` (exit 0), `drift` (exit 1), or usage errors (exit 2).
JSON includes `clis`, `rc_token_findings`, `automation_misuse`, `gemini_legacy`,
`verdict`, `reasons`, and `next_steps`. Unknown agy login alone is not drift.
Findings include only file and line, never values. It inspects `.bashrc`,
`.profile`, `.bash_profile`, `.zshrc`, `.config/environment.d/*`,
`/etc/environment`, and `/etc/profile.d/*` for assignments of
`CLAUDE_CODE_OAUTH_TOKEN`, `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`,
`OPENAI_API_KEY`, `XAI_API_KEY`, and `GEMINI_API_KEY`. Remove such assignments
privately. It also checks crontab and user systemd service files for bare
Claude print commands. These text checks are heuristics, not shell parsers.

## Fleet reports

Put one SSH alias per line in `hosts.txt`; `#` comments are allowed:

```text
host-a
host-b
```

```bash
ops/fleet/fleet-run.sh --hosts hosts.txt --out reports/ai-cli -- ops/fleet/ai-cli/check-ai-clis.sh --json
ops/fleet/fleet-report.sh reports/ai-cli > reports/ai-cli.md
```

The helper sends the local script over SSH stdin. Remote hosts need bash and
python3 for the checker. SSH uses BatchMode and disables agent forwarding.
Each host has a 180-second timeout and separate `.out` and `.rc` files.
A failed host does not stop remaining hosts. The helper exits 1 if any host
returns nonzero, including checker drift. `--ssh CMD` selects an alternate
SSH executable. Arguments are quoted for the remote shell.

Use this helper for scripts whose output is safe to store and summarize.
The checker produces sanitized output. Generic scripts must uphold the same
rule: never print secrets. Report directories are mode 700 and new output
files are mode 600. The report renders malformed or failed output as unknown.

## Agent credential observations

The historical `gemini` credential slot represents agy. The agent reads only
`~/.gemini/antigravity-cli/antigravity-oauth-token`; legacy
`~/.gemini/oauth_creds.json` is ignored. The agy file must be regular, not a
symlink, owned by the agent user, and have no group/other permission bits.
Valid JSON with a non-empty `token.refresh_token` is `configured`, with note
"refreshable; access token refreshed on use" and no `expires_at`. An expired
one-hour access token is normal: agy refreshes on use. Without a refresh token,
`token.expiry` (RFC3339, including nanoseconds and offsets) is judged normally.
Malformed JSON is `unknown`; the Hub treats it as a non-advisory finding.

For Claude, `~/.config/claude-automation/oauth-token` is authoritative whenever
present. The agent requires a regular, user-owned, non-symlink file with mode
0600 and one line matching `^sk-ant-oat[0-9A-Za-z_-]{20,400}$` (a final newline
is allowed). This probe intentionally requires 0600 even though the wrapper
also accepts 0400. A valid file is `configured`, with note "long-lived
claude-automation token; expiry not encoded" and no `expires_at`. Only absence
permits fallback to `~/.claude/.credentials.json`. Invalid files produce
non-advisory findings with non-secret reasons. No Claude command or API is
called by credential probes; token values are never reported or hashed.

The additive credential `source` field is `agy` or `claude-automation` for
these files. Existing Hubs understand `configured` without expiry. New Hubs
ignore source-less legacy Gemini credentials when the machine reports agy
present, while still judging invalid agy credentials. Other providers retain
their existing judgement.

Grok auth entries under `https://auth.x.ai::*` with an expired access token
and a non-empty `refresh_token` are reported as `configured`/refreshable when
`expires_at` is at most 30 days in the past. Access-token expiry is omitted
from these observations, so Hub judgement and notifications do not treat
expiry before the next CLI use as a login failure. Grok refreshes on every
use; expiry more than 30 days in the past indicates that the refresh chain
has stopped and remains `expired`, even with a refresh token. Without a
refresh token, expiry is judged normally; missing auth files remain `absent`.
Claude and Codex expiry judgement is unchanged, including when refresh tokens
are present. These probes read files only and never perform a model or network call.

## Sign in from the Hub

Open **Sign-ins** to see accounts across the fleet, grouped by CLI and plain
account email where available. Unknown identities group by account slot. The
navigation badge counts expired, failing, and soon-expiring sign-ins. Healthy
accounts are under **Signed in**. Local credential files are evidence of saved
configuration, not proof that the provider accepts a request. A login process
that reports an authentication failure marks that account as failing even if a
local credential file remains.

An administrator chooses **Sign in** beside a machine, or **Sign in all** for
supported flows. Local account administrators confirm fresh MFA first. Open each
host's sign-in link in a new tab and use its one-time device code, or paste the
authorization code into the Hub when prompted. Each machine has its own flow.
The page refreshes while work is active, pausing while you enter a code; cancel
from the same panel. Without JavaScript, refresh to check progress. Sessions
expire after 15 minutes, with at most four concurrent logins per Linux host.

Codex uses device authorization; agy selects Google OAuth and accepts a pasted
code; Claude runs `claude setup-token`; GitHub uses its web device flow followed
by `gh auth setup-git`. Grok accepts paste-back when offered; a localhost-only
callback requires finishing in a browser on that machine. Claude setup-token
versions that only print a token do not save the automation credential: that
token is discarded, and the existing private automation-token setup is still
required. Hermes openai-codex status is unknown because this tree has no stable
read-only auth-store contract; Hub sign-in is unsupported.

The agent starts login PTYs through `systemd-run --user` services, outside the
agent unit's ProtectHome/NoNewPrivileges sandbox, as the same OS user. The user
manager must be available. PATH includes the real user's `.local/bin` and
`.grok/bin`; agy slots 2–8 override HOME to the corresponding
`.gemini/antigravity-accounts/acctN-home` directory. Whole service control groups
are stopped on timeout, cancellation, or agent shutdown. macOS and Windows
report status but do not support Hub-started login.

Only allowlisted HTTPS login URLs and device codes leave the PTY. Raw output
and credential tokens are discarded. Pasted authorization codes live only in
Hub memory until one delivery; they never enter the database or audit. A lost
delivery or Hub restart requires a new flow. Pages are no-store. The View API
`GET /v1/operator/signins` and read-only MCP `signins_list` return account status
only, without login URLs or codes.

Notifications default to Off. Choose an existing channel on Sign-ins to receive
a message when a saved status changes from ok/expiring to logged out, at most
once per machine/CLI/slot every 12 hours. Configure destinations in Channels.

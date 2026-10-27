# Windows agent logging

Windows bootstrap binaries (amd64 and arm64) use Go's `-H=windowsgui`
linker flag. The daemon does not allocate or attach a console by default.
The scheduled task still directly executes the agent, uses a LogonTrigger,
InteractiveToken and LeastPrivilege, and requires an interactive user logon.
No stored password is used. `<Hidden>true</Hidden>` hides the task in Task
Scheduler's UI; the GUI subsystem prevents the agent console window.

The daemon writes standard Go logs, including fatal errors and recovered
main-goroutine panic stacks, to
`%LOCALAPPDATA%\clawctl\logs\agent.log`. Rotation occurs before a write would
exceed 5 MiB, retaining five historical files (`agent.log.1` through `.5`).
An individual oversized log record is kept intact. Raw OS stderr and Go
runtime fatal/unrecovered panic output go to `agent-crash.log` in the same
directory, using stderr redirection plus `debug.SetCrashOutput`. This separate
append-only crash file is not rotated while open; inspect/archive it when the
agent is stopped. Runtime crash traces can appear twice because both sinks
capture them. Logging initialization failures terminate startup.

`clawctl-agent log-path` prints the absolute default `agent.log` path on one
line without starting the daemon or creating files. Prefix any command with
`--console` to attach an existing parent console; for the daemon this also
mirrors Go logs to stderr. No console is allocated. CLI commands automatically
attempt parent-console attachment and preserve redirected output pipes/files
for PowerShell and installer capture. Windows GUI programs may require
PowerShell `Start-Process -Wait` or the call operator with output capture when
waiting for completion; actual Windows console behavior needs Windows runtime
validation. Linux and macOS retain their existing stderr logging.

Join `-Proxy` saves `proxy_url` before the scheduled task starts. The configured
proxy takes precedence over environment proxies and survives reinstall or upgrade.
Without `-Proxy`, join writes no `proxy_url`; an empty proxy configuration uses
the environment proxy settings. See [proxy setup](WINDOWS-AGENT-VALIDATION.md#corporate-proxy).

To roll back, first retain the previous agent binary, exported scheduled-task
XML and `agent.json`. Restore those three artifacts and restart the task or log
on again. Restoring XML/configuration alone does not undo the binary's GUI
subsystem. These are operator instructions, not deployment performed by this PR.

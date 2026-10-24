# Fleet health probe

The read-only `fleet-probe-v2` catalog script runs as the agent user on Linux
and macOS. It takes `{}` as its arguments, defaults to 15 seconds, permits up
to 60 seconds, and caps output at 64 KiB.

Each run returns one JSON line containing `os`, `uptime_seconds`, three
`load` values, `root_disk_use_percent`, and `failed_service_count`. The service
count is null when the service manager cannot be queried. Linux counts failed
systemd units; macOS counts launchctl rows with nonzero integer exit status.
macOS disk usage covers /System/Volumes/Data when present, otherwise /.

To include macOS machines in an existing daily health schedule:

1. Install a Hub and user agent build containing fleet-probe-v2. Confirm the
   agents advertise script_v1 and have jobs enabled.
2. Open Schedules, edit fleet-daily-health, select fleet-probe-v2, and use {}.
3. Select the Linux and macOS targets, preview, and apply the schedule.

The preview validates the targets and catalog digest. Existing schedules keep
their pinned script and digest until an operator applies an edit.
fleet-probe-v1 and its digest remain unchanged.

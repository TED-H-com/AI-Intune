# Hermes token rotation

On the Hub, sign in as an admin with MFA. Open Account security → Service tokens.
Use name `hermes`, scope `operate`, expiry 90 days, and optionally a maximum chain
lifetime of 180 or 365 days. Click **Create with Hermes default**. Save the token
immediately; it appears only once.

On the Hermes host, install the operator binary at
`~/.local/bin/clawctl-operator`. Create `~/.config/hermes` with mode 0700 and save
the credential in `~/.config/hermes/service-token` with mode 0600 (regular file,
no symlink). Put `HERMES_HUB_ORIGIN=https://hub.example.com` in
`~/.config/hermes/hub.env`, using your HTTPS Hub origin.

Copy these service and timer files to `~/.config/systemd/user/`, then run:

```sh
systemctl --user daemon-reload
systemctl --user enable --now service-token-rotate.timer
systemctl --user start service-token-rotate.service
journalctl --user -u service-token-rotate.service
```

Configure user lingering through your host administrator if the timer should run
while logged out. No token is printed by the command. Reload long-running Hermes
clients after rotation so they reread the file within the 10-minute overlap.
The timer does not restart those clients.

Exit codes: 0 = rotated or not due; 1 = file, network, Hub, or persistence error;
2 = invalid command/options. A failed file replacement leaves the old token usable
for the original overlap. Rename or file-fsync failure preserves a mode-0600
recovery token file and reports its path; install it promptly, fsync the directory,
then authenticate with GET self (a new command using that file does so). Directory
fsync failure reports the destination containing the new token; sync the directory
before retrying authentication. The CLI confirms GET self after successful install.

If the response was lost or the client crashed before installation, re-run rotation
with the predecessor during the original overlap (use `--force` if the original
rotation was forced). While the successor is unused, this revokes it and issues a
fresh one, subject to the shared three/hour chain/IP budget. Once the successor
has authenticated, the predecessor returns 409. The newest token cannot rotate
until its predecessor's overlap ends. When the maximum chain lifetime
is reached, create a new token through the admin page.

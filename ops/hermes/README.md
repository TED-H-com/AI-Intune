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
for the overlap; fix the file problem promptly. The newest token alone can rotate;
repeating rotation with the old token returns 409. When the maximum chain lifetime
is reached, create a new token through the admin page.

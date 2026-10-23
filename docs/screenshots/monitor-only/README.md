Synthetic SSR evidence for monitor-only machine detail and profile confirmation,
at 390, 768 and 1440 pixels. Fixtures use an empty synthetic tailnet snapshot,
fixed display values and inert request keys; they contain no live Hub data.

Regenerate with the repository Go toolchain and a local Chromium executable:

```sh
umask 0022
CLAWCTL_SCREENSHOT_BROWSER=/path/to/chromium bash ops/screenshots/monitor-only.sh
```

The script renders tests and opens local HTML files. No Hub login or live call.

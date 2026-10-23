# Checks UI evidence

Generated from local SSR fixtures, with no Hub requests or credentials.

Run with Go on PATH:

```sh
CLAWCTL_SCREENSHOT_BROWSER=/path/to/chrome-headless-shell bash ops/screenshots/report-checks.sh
```

The fixtures cover fleet results, the machine's Checks section, and the five
independent disabled schedule confirmations at 390, 768 and 1440 pixels.
Tables scroll within their panel on narrow screens. Status always includes text.
The example network finding contains deliberately private output in the test;
only its fixed sentence and allowlisted metrics reach the rendered HTML.

The new network bytes add online counts and explicit baseline/comparison flags.
Old receipts display unknown for these fields. Schedules pinned to the previous
network hash require a separate reviewed update; nothing is enabled here.

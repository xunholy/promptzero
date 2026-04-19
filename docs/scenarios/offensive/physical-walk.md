# Physical pentest — badge walk

## Continuous RFID + NFC + iButton census

> *"Start a physical pentest badge walk — keep scanning for 300
> seconds, dedupe unique UIDs, and write results to
> /ext/pentest/walk_$(date).csv"*

Fires `workflow_phys_pentest_badge_walk(duration_seconds=300,
dedupe_window_seconds=0, csv_path=/ext/pentest/walk_…csv)`.

Behaviour:
- Loops per-technology scans roughly every 5s (NFC → RFID → iButton).
- Logs each unique UID with timestamp, protocol, technology.
- Dedupes within the configured window (0 = dedupe for the whole
  run).
- Stops when `duration_seconds` elapses OR the turn is cancelled.

The tool returns the CSV summary inline so you can see the UID
count in the response, and the full CSV sits on the SD card.

## Stopping early

In the REPL, press Ctrl+C once to cancel the in-flight turn — the
workflow respects context cancellation and flushes whatever it has
to the CSV.

## Parameter notes

- `duration_seconds` clamped to 30–1800 (0.5s–30min).
- `dedupe_window_seconds`: set to e.g. 60 if you want the same UID
  re-logged whenever it's seen after a minute has passed (useful
  for "which badges are active right now?").
- `csv_path` defaults to `/ext/badge_walk_<unix>.csv`.

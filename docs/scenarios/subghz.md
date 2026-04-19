# Sub-GHz scenarios

Receive is safe. Transmit requires authorisation for the target
device and, in most regions, a licence for the frequency.

## Listen for activity on a frequency

> *"Do a quick receive on 433.92MHz for 5 seconds and tell me if
> anything's in the air"*

Fires `subghz_receive(frequency=433920000, duration_seconds=5)`.
Returns a short summary — "Quiet" or "Captured N frames".
[Transcript 06](../transcripts/06-subghz-rx.json)

## Raw pulse capture (Momentum only)

When the decoder can't make sense of a signal and you want to see the
raw waveform:

> *"Record raw Sub-GHz pulses on 433.92MHz for 3 seconds and dump the
> raw data (don't save to SD)"*

Fires `subghz_rx_raw`. Values come back as microsecond pulse
durations (`+high -low …`). Stock/Unleashed/Xtreme users will get a
friendly error — those forks don't expose the `rx_raw` CLI. Use
`subghz_receive` plus `storage_read` on the resulting `.sub` instead.
[Transcript 24](../transcripts/24-subghz-rx-raw.json)

## Decode a saved capture

> *"Decode /ext/subghz/Tesla/Tesla_US_AM650.sub — show me the protocol,
> frequency and whatever key data you can extract"*

Fires `subghz_decode` (and often `fileformat_read` to pull structural
fields). Works for protocol-decoded captures (Princeton, Keeloq,
CAME, Nice, …) and for RAW ones (it'll tell you they're RAW and
print the preset/frequency).
[Transcript 30](../transcripts/30-subghz-decode.json)

## Compare two captures

> *"Diff the two Tesla EU sub files in /ext/subghz/Tesla — what's
> different between AM270 and AM650?"*

Fires `fileformat_diff`. Per-field, per-block diff of the two parsed
files. Great for "is this capture stable across takes?" or "which
preset differs?".
[Transcript 19](../transcripts/19-fileformat-diff.json)

## Triage an unknown remote / garage-door sweep

> *"Do a garage-door triage sweep — listen on all the common garage
> and car remote frequencies and tell me what you hear. Use 3 seconds
> per frequency."*

Fires `workflow_garage_door_triage`. Scans 300/310/315/318/390/
433.92/868.35 MHz back-to-back, saves each capture, and returns a
table of what was decoded where.
[Transcript 16](../transcripts/16-workflow-garage.json)

The workflow **does not transmit**. Captures land in `/ext/subghz/`
as `triage_<freq>_<unix>.sub` — clean them up with
*"Delete any triage_*.sub files in /ext/subghz"* when you're done
([transcript 33](../transcripts/33-cleanup-triage.json)).

## Transmit a saved signal (high risk)

See [`offensive/subghz-tx.md`](offensive/subghz-tx.md). Short version:

> *"Transmit /ext/subghz/garage.sub"*

Fires `subghz_transmit` — classified `critical`, confirmation-gated.
Only run with authorisation for the receiver.

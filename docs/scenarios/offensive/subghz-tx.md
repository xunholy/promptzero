# Sub-GHz transmit scenarios

## Transmit a saved capture

> *"Transmit /ext/subghz/garage.sub"*

Fires `subghz_transmit(file=…)`. Classified `critical`. The agent
will ask you to confirm before firing.

When your config has a `devices:` map, use friendly names:

```yaml
# ~/.promptzero/config.yaml
devices:
  garage: /ext/subghz/garage.sub
  gate:   /ext/subghz/side_gate.sub
```

> *"Open the garage"* → the agent looks up `garage` → fires
> `subghz_transmit(/ext/subghz/garage.sub)`.

## Transmit a raw key

> *"Transmit the key F00F00AA on 433.92MHz with 400µs timing,
> repeated 5 times"*

Fires `subghz_tx_key(key_hex=F00F00AA, frequency=433920000, te=400,
repeat=5)`. Used for:
- Replay attacks where the `.sub` format isn't worth it.
- Protocol experimentation — try a candidate key on a target.
- Fuzzing a receiver with close variants.

## Brute-force a rolling-code receiver (heavy, typically illegal)

> *"Brute-force /ext/subghz/captured.sub on 433.92MHz for 60 seconds"*

Fires `subghz_bruteforce`. Classified `critical`.

The separately-registered `loader_subghz_bruteforcer` FAP is the
preferred way to run large code sweeps across many protocols:

> *"Launch the Sub-GHz Bruteforcer FAP"* → `loader_subghz_bruteforcer`.
Requires the FAP installed.

## Playlist (chained transmits)

> *"Launch the Sub-GHz Playlist to replay my captures in order"*

Fires `loader_subghz_playlist`. Requires the FAP installed and a
playlist file configured.

## Sub-GHz chat (every keystroke transmits)

> *"Join Sub-GHz chat on 433.92 MHz for 60 seconds"*

Fires `subghz_chat(frequency=433920000, duration_seconds=60)`.
Every keystroke goes out on air until the duration elapses.

## The garage-door triage workflow does NOT transmit

[Transcript 16](../../transcripts/16-workflow-garage.json) for
reference. It sweeps frequencies RX-only and writes captures to
`/ext/subghz/triage_*.sub`. Transmitting the resulting files is a
separate, explicit step — pass the file path back with
`subghz_transmit`.

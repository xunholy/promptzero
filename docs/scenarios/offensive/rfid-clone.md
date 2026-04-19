# RFID (125 kHz) clone scenarios

## Read, then emulate

> *"Read a 125kHz RFID fob and then emulate it so I can wave the
> Flipper at a reader instead"*

Chain: `rfid_read` → `rfid_emulate(protocol=…, data=…)`. Emulate is
`high` — active emission. The agent pulls protocol + data from the
read result and threads it into the emulate call.

## Clone to a T5577 blank

> *"Clone the EM4100 card I just read onto the T5577 blank I'm
> holding against the back"*

Fires `rfid_write(protocol=EM4100, data=<hex>)`. Classified
`critical`. Destructive to the T5577 — the old block 0 and config
are overwritten with the new UID.

## Batch-write a list of blanks

> *"Launch the T5577 Multiwriter FAP"* → `loader_t5577_multiwriter`.
Requires the FAP installed. Drives a list of protocol/data
combinations from a file.

## Raw LF capture for reverse engineering

> *"Do a raw LF capture to /ext/lfrfid/raw_01.raw for 10 seconds —
> I'm holding a non-standard fob"*

Fires `rfid_raw_read(file=…, duration_seconds=10)`. Unprocessed
bitstream; use when the protocol auto-detect misses.

Decode offline:

> *"Analyse /ext/lfrfid/raw_01.raw and tell me the protocol"* →
> `rfid_raw_analyze`.

Replay:

> *"Replay /ext/lfrfid/raw_01.raw at the reader for 30 seconds"* →
> `rfid_raw_emulate`. Classified `critical`.

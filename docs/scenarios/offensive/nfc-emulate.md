# NFC emulate / write scenarios

## Emulate a saved tag

> *"Emulate /ext/nfc/office_badge.nfc"*

Fires `nfc_emulate(file=…)`. Classified `critical`. The Flipper holds
the tag profile in memory and responds to a reader's field. Hold the
Flipper where the real tag would go.

## Write to a MIFARE Ultralight / NTAG page

> *"Write the bytes DEADBEEF to page 6 of the MIFARE Ultralight held
> against the back"*

Fires `nfc_mfu_wrbl(page=6, hex=DEADBEEF)`. **Destructive** — the old
page contents are gone. Pages 0–2 are typically the UID + lock bytes
and are one-way on most tags. Fork-gated on the `nfc` CLI subshell
(Stock / Unleashed / RogueMaster; not Xtreme).

## Clone a MIFARE Classic (with keys you've recovered)

Two-step flow. First recover keys:

> *"Launch MFKey32 to recover MIFARE Classic sector keys from the
> reader nonces I've captured"* → `loader_mfkey`.

Or when only one key is known:

> *"Launch Mifare Nested to nest-attack the remaining sectors"* →
> `loader_mifare_nested`.

Then clone onto a magic tag:

> *"Launch NFC Magic to write the dumped UID to my magic MIFARE"* →
> `loader_nfc_magic`.

All three loader tools require the respective FAP installed.

## PicoPass / HID iClass

> *"Launch the PicoPass tool"* → `loader_picopass`.
> *"Launch SEADER for iClass SE"* → `loader_seader`.

## Raw NFC experimentation

See [`../nfc-rfid.md#send-raw-frames`](../nfc-rfid.md). Classified
`high` rather than `critical` because raw frames to an already-held
tag are reversible in context — but they can still write pages on
writable tags, so treat with care.

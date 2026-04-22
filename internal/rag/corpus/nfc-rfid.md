# NFC / RFID / iButton scenarios

Three distinct technologies, often confused:

- **NFC (13.56 MHz)** — MIFARE, NTAG, DESFire, EMV bank cards,
  transit cards. Antenna on the back of the Flipper.
- **125 kHz RFID (LF)** — prox cards, HID, Indala, EM4100. Same
  back antenna, different resonance.
- **iButton / 1-Wire** — Dallas keys. Contact pad on the top-left
  corner.

## Detect an unknown 13.56 MHz tag

> *"Try to detect an NFC tag for 8 seconds"*

Fires `nfc_detect(timeout_seconds=8)`. Returns type, UID, ATQA, SAK
when it sees one. [Transcript 09](../transcripts/09-nfc-detect.json)

Tips:
- Hold the tag flat against the **back** of the Flipper, roughly centre.
- A phone in a case, a wallet card in front, or another tag nearby
  will kill detection.

## Triage an unknown badge (recommended)

> *"I'm holding an unknown NFC badge against the back of the Flipper —
> run the badge-triage workflow on it with a 8 second timeout, and
> do NOT dump yet."*

Fires `workflow_nfc_badge_pipeline(attempt_dump=false, timeout_seconds=8)`.
Detects → parses protocol → suggests next step (MFKey32 for MIFARE
Classic, block reads for Ultralight, APDU recon for DESFire/EMV).
When you're ready to go deeper, re-run with `attempt_dump=true`.
[Transcript 26](../transcripts/26-workflow-nfc.json)

## Read a 125 kHz prox card

> *"Try to read a 125kHz RFID fob — I'm holding one against the back
> of the Flipper. Give it 8 seconds max."*

Fires `rfid_read(timeout_seconds=8)`. The tool auto-detects across
EM4100, HIDProx, Indala, AWID, FDX-A, FDX-B.
[Transcript 08](../transcripts/08-rfid-read.json)

If the initial auto-detect misses, try pinning the mode:
`"…try ASK mode"` or `"…try PSK mode"` — the agent passes it through.

## Read an iButton / Dallas key

Two angles work:

> *"Scan for iButton keys for 8 seconds"*
> → fires `onewire_search`. The generic 1-Wire enumerator.
> [Transcript 10](../transcripts/10-ibutton-read.json)

> *"Read a Dallas iButton key — I've got one touching the pad"*
> → fires `ibutton_read`. Returns the decoded protocol + hex data.

If `ibutton_read` times out but `onewire_search` found ROM codes,
the key is there but the protocol decoder didn't recognise it —
that's often a Cyfral or Metakom key on a reader expecting Dallas.

## Dump tag contents

MIFARE Ultralight / NTAG, single page:

> *"Read page 4 of the NFC tag held against the back"*

Fires `nfc_mfu_rdbl(page=4)`. Fork-gated (Stock / Unleashed /
RogueMaster — not Xtreme).

Full protocol dump:

> *"Dump all readable contents of the MIFARE Ultralight tag"*

Fires `nfc_dump_protocol(protocol=Mifare_Ultralight)`.

## Send raw frames (protocol experimentation)

> *"Send the raw ISO14443 frame 30 04 to the tag and show me the
> response"*

Fires `nfc_raw_frame(hex="30 04")`. That specific frame is a
`READ page 4` against Ultralight/NTAG; useful when you know the
exact command you want and don't want the high-level tool to decide.

EMV / DESFire APDUs:

> *"Send the PPSE select APDU (00A404000E325041592E5359532E4444463031)
> to the contactless card I've got held up"*

Fires `nfc_apdu`.

## Transmit / emulate (high risk)

Emulating or writing a tag is active emission — see
[`offensive/nfc-emulate.md`](offensive/nfc-emulate.md).

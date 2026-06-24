# Inventory — what do I have?

Everything here is read-only. No RF, no writes, no reboots.

## What apps are on my Flipper?

> *"What apps are installed on my Flipper?"*

Fires `list_apps`. Returns built-ins (Sub-GHz, NFC, RFID, iButton,
Infrared, GPIO, Bad KB, U2F, Momentum) and any settings-menu entries.
FAPs installed under `/ext/apps/` also show up.
[Transcript 02](../transcripts/02-list-apps.json)

## What's on the SD card?

Quick top-level:

> *"List the files at /ext on my Flipper and tell me what's there"*

Full categorised inventory (apps + saved captures + config):

> *"Do a full discover of what's on my SD card — apps, saved signals,
> everything. Give me a categorized inventory."*

Fires `discover_apps`, which walks the whole card and groups results
by subsystem.
[Transcript 21](../transcripts/21-discover.json)

Recursive single-directory dump:

> *"Show me everything under /ext/subghz — files and folders,
> recursively"*

Fires `storage_tree /ext/subghz`.
[Transcript 03](../transcripts/03-storage-tree.json)

## Device metadata

Firmware / hardware / radio:

> *"What's my Flipper's firmware version and hardware revision?"*

Fires `device_info`. On Momentum you'll see the fork in the
`firmware_origin_fork` field.

Battery:

> *"What's the battery level and is it charging?"*

Fires `power_info`. Returns charge %, voltage, current, temperature,
health. [Transcript 29](../transcripts/29-power.json)

Bluetooth chip:

> *"Tell me my Flipper's Bluetooth controller info — chip, firmware,
> MAC"*

Fires `bt_hci_info`. Returns HCI version / manufacturer / subversion.
MAC is only exposed on Momentum's `info bt` command on some builds;
the agent flags the gap when it's missing.
[Transcript 35](../transcripts/35-bt-info.json)

## Named devices from your config

If you've set up a `devices:` map in `config.yaml`:

> *"List my configured devices — the named ones I've mapped to
> signal files"*

Fires `list_devices`. Useful to discover what was in your config
without opening the file — or, when empty, as a jumping-off point for
setting the map up. [Transcript 20](../transcripts/20-list-devices.json)

## File integrity

> *"Compute the MD5 of /ext/subghz/Tesla/Tesla_EU_AM270.sub"*

Fires `storage_md5`. 32-char hex. Use it to confirm a capture matches
a known-good copy, or to diff against a file you just wrote via
`generate_subghz`. [Transcript 34](../transcripts/34-storage-md5.json)

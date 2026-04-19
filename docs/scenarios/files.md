# Files / storage scenarios

## List a directory

> *"List the files at /ext on my Flipper and tell me what's there"*
> → `storage_list /ext`. [Transcript 01](../transcripts/01-storage-list.json)

## Recursive walk

> *"Show me everything under /ext/subghz — files and folders,
> recursively"*
> → `storage_tree /ext/subghz`.
> [Transcript 03](../transcripts/03-storage-tree.json)

## Read a file

> *"Read /ext/subghz/Tesla/Tesla_US_AM650.sub and show me the raw
> contents"*
> → `storage_read`. Prefer `fileformat_read` if you want structured
> fields rather than raw text.

## Hash / verify

> *"Compute the MD5 of /ext/subghz/Tesla/Tesla_EU_AM270.sub"*
> → `storage_md5`. [Transcript 34](../transcripts/34-storage-md5.json)

## Copy / rename

> *"Copy /ext/subghz/Tesla/Tesla_EU_AM270.sub to /ext/pztest_edit.sub"*
> → `storage_copy`.

> *"Rename /ext/badusb/old.txt to /ext/badusb/new.txt"*
> → `storage_rename`.

## Delete (classified `high`)

> *"Delete /ext/badusb/hello_pztest.txt"*
> → `storage_delete`. Confirmation-gated unless `--yolo`.

Batch cleanup with a pattern — the agent will list first, then
delete individually:

> *"Find and delete any triage_*.sub files left in /ext/subghz from
> earlier scans"*

Fires `storage_tree /ext/subghz` → one `storage_delete` per match.
[Transcript 33](../transcripts/33-cleanup-triage.json)

## Structural read

For `.sub` / `.nfc` / `.ir` / `.rfid` files, parse fields rather than
string-search:

> *"Decode the Tesla_EU_AM270.sub file on my Flipper — what protocol,
> frequency and key does it use?"*
> → `fileformat_read`. [Transcript 05](../transcripts/05-fileformat-read.json)

## Structural diff

> *"Diff the two Tesla EU sub files in /ext/subghz/Tesla — what's
> different between AM270 and AM650?"*
> → `fileformat_diff`.
> [Transcript 19](../transcripts/19-fileformat-diff.json)

Format mismatches (e.g. diffing a `.sub` against an `.nfc`) return
`{same_format: false}` with no entries.

## Structural edit

`fileformat_edit` applies a top-level edits map and re-serialises.
Allowed keys per format are documented in the tool description.

> *"Change the frequency in /ext/subghz/garage.sub from 315000000 to
> 433920000"*

Fires `fileformat_edit(path=…, edits={frequency: 433920000})`.

> ⚠️ **Known issue:** multi-`RAW_Data` `.sub` files (garage triage
> captures, any manual raw recording) lose all RAW_Data lines except
> the first on save. Agent recovered gracefully in
> [transcript 27](../transcripts/27-fileformat-edit.json) but it's
> worth knowing. Workaround: `storage_copy` + hand-edit, or use the
> Flipper UI.

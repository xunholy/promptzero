# Contributing to the Flipper Zero Catalog

Thank you for helping grow the most comprehensive Flipper Zero ecosystem catalog!
This guide covers everything you need to add or update an entry.

---

## Quick start (2 minutes)

1. **Fork** the [promptzero repo](https://github.com/xunholy/promptzero) and create a branch.
2. **Find the right file** — see [Where to add entries](#where-to-add-entries) below.
3. **Add one row** to the Markdown table in the appropriate `.md` file.
4. **Open a PR** — the schema validator runs automatically on every PR that touches `docs/catalog/`.

That's it. The CI job (`catalog-refresh.yml`) will validate your row and flag any issues inline.

---

## Entry format

Each catalog file contains one or more Markdown tables with these columns:

```
| Name | URL | Author | Stars | Last Commit | License | Status | Notes |
|------|-----|--------|-------|-------------|---------|--------|-------|
| Example Tool | https://github.com/org/repo | org | 1234 | 2025-11 | MIT | active | Short description |
```

### Column definitions

| Column | Required | Format | Description |
|--------|----------|--------|-------------|
| **Name** | ✅ | Free text | Human-readable project name. Use the official name from the repo. |
| **URL** | ✅ | `https://…` | Canonical HTTPS URL. GitHub repos: use `https://github.com/org/repo`. |
| **Author** | ✅ | GitHub handle/org | Primary maintainer's GitHub username or organisation. |
| **Stars** | ❌ | Integer or `N/A` | GitHub star count at time of submission. Use `N/A` for non-GitHub resources. |
| **Last Commit** | ❌ | `YYYY-MM` | Month of last repository commit. Use `N/A` for non-repo resources. |
| **License** | ❌ | SPDX ID or `N/A` | SPDX identifier (e.g. `MIT`, `GPL-3.0`, `Apache-2.0`). `N/A` for communities, docs, etc. |
| **Status** | ✅ | See [Status field rules](#status-field-rules) | Lifecycle status of the project. |
| **Notes** | ✅ | Free text (≤120 chars) | One-sentence description of what the project does and why it matters. |

---

## Where to add entries

| Section | File |
|---------|------|
| Firmware — OFW | `docs/catalog/firmware/ofw.md` |
| Firmware — Unleashed | `docs/catalog/firmware/unleashed.md` |
| Firmware — Momentum | `docs/catalog/firmware/momentum.md` |
| Firmware — RogueMaster | `docs/catalog/firmware/roguemaster.md` |
| FAPs — NFC | `docs/catalog/faps/nfc.md` |
| FAPs — Sub-GHz | `docs/catalog/faps/subghz.md` |
| FAPs — Infrared | `docs/catalog/faps/ir.md` |
| FAPs — Bad USB | `docs/catalog/faps/badusb.md` |
| FAPs — Bluetooth / BLE | `docs/catalog/faps/ble.md` |
| FAPs — GPIO | `docs/catalog/faps/gpio.md` |
| FAPs — Games & Misc | `docs/catalog/faps/misc.md` |
| Payloads — Sub-GHz | `docs/catalog/payloads/subghz.md` |
| Payloads — NFC / RFID | `docs/catalog/payloads/nfc.md` |
| Payloads — Infrared | `docs/catalog/payloads/ir.md` |
| Payloads — Bad USB | `docs/catalog/payloads/badusb.md` |
| Tools — Desktop | `docs/catalog/tools/desktop.md` |
| Tools — Mobile | `docs/catalog/tools/mobile.md` |
| Tools — Web | `docs/catalog/tools/web.md` |
| Tools — CLI | `docs/catalog/tools/cli.md` |
| Hardware — Companion Boards | `docs/catalog/hardware-mods/boards.md` |
| Hardware — Antennas & Modules | `docs/catalog/hardware-mods/antennas.md` |
| Hardware — 3D Prints | `docs/catalog/hardware-mods/prints.md` |
| Hardware — Research Platforms | `docs/catalog/hardware-mods/research.md` |
| Community — Discord / Matrix | `docs/catalog/community/chat.md` |
| Community — Forums & Reddit | `docs/catalog/community/forums.md` |
| Community — YouTube / Streams | `docs/catalog/community/media.md` |
| Community — Guides & Wikis | `docs/catalog/community/guides.md` |
| Research — Papers | `docs/catalog/research/papers.md` |
| Research — CVEs | `docs/catalog/research/cves.md` |
| Research — CTF Challenges | `docs/catalog/research/ctf.md` |
| Educational — Courses & Books | `docs/catalog/educational/courses.md` |
| Educational — Tutorials | `docs/catalog/educational/tutorials.md` |
| Integrations — AI / Automation | `docs/catalog/integrations/ai.md` |
| Adversarial | `docs/catalog/adversarial/README.md` |

---

## Schema validation

Every PR that touches `docs/catalog/` runs `scripts/catalog_validate.py` automatically
via the `catalog-refresh.yml` GitHub Actions workflow. The job will fail (and block merge)
if your entry contains:

- A malformed or non-HTTPS URL
- An invalid `status` value
- An empty `Name` field
- A duplicate URL within the same file

### Running locally

```bash
python scripts/catalog_validate.py docs/catalog/
```

Expected output on success:

```
✅ Validation PASSED: 34 catalog files checked, 0 errors
```

On failure:

```
❌ Validation FAILED: 2 error(s) in 34 files checked

  docs/catalog/payloads/subghz.md:47: Invalid status: 'activee' (must be one of ['active', 'adversarial', 'archived', 'stale'])
  docs/catalog/tools/desktop.md:23: Malformed URL: 'htp://example.com'
```

Fix any reported errors before pushing your branch.

---

## Status field rules

| Status | Criteria |
|--------|----------|
| `active` | Last commit within **12 months** of the catalog snapshot date |
| `stale` | Last commit **12–36 months** ago |
| `archived` | Explicitly archived on GitHub **or** no activity for **>36 months** |
| `adversarial` | Entry describes offensive tooling with exploitation intent — see [adversarial/README.md](../adversarial/README.md) for the full policy |

When in doubt, check the repo's GitHub page. If it shows the "Archived" badge, use `archived`.

---

## URL policies

- All URLs **must be publicly accessible** (no paywalls, no login-required links).
- GitHub repos: always use the canonical HTTPS URL (`https://github.com/org/repo`), not a
  shortened link or redirect.
- **Archived repos** remain linkable — use status `archived`.
- **Adversarial entries**: some URLs may be withheld per policy. See
  [adversarial/README.md](../adversarial/README.md) for the URL-withholding guidelines
  and the `[URL WITHHELD]` placeholder convention.

---

## Pull request checklist

Before opening your PR, verify:

- [ ] Entry added to the correct file (see [Where to add entries](#where-to-add-entries))
- [ ] All 8 columns populated: Name, URL, Author, Stars, Last Commit, License, Status, Notes
- [ ] Status matches the criteria in [Status field rules](#status-field-rules)
- [ ] No duplicate entries — search existing tables first (`grep -r "github.com/org/repo" docs/catalog/`)
- [ ] `python scripts/catalog_validate.py docs/catalog/` passes locally with 0 errors
- [ ] PR title follows the format: `catalog: add <Name>` or `catalog: update <Name>`

---

## Reporting dead links

If you find a link that no longer works:

1. Open an issue with the title: `[DEAD LINK] <Name>`
2. Include the file path and the broken URL in the issue body.
3. If you know the new URL (e.g. repo was moved/renamed), include that too.

The nightly `catalog-refresh.yml` workflow also performs automated link checking and will
open issues for persistent dead links detected over multiple runs.

---

## Adversarial entries

Entries that document offensive capabilities, exploitation tools, or active attack
infrastructure require special handling. See
[adversarial/README.md](../adversarial/README.md) for:

- What qualifies as adversarial
- The URL-withholding policy
- The responsible disclosure requirement

When filing issues related to adversarial content, use the `[ADVERSARIAL]` prefix in
the issue title, e.g.: `[ADVERSARIAL] New BadUSB payload dropper`.

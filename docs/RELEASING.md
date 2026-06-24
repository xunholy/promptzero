# Releasing PromptZero

Releases are cut by pushing a `v*` tag. The GitHub Actions workflow
at `.github/workflows/release.yaml` builds five platform binaries,
signs checksums with cosign (keyless), generates a CycloneDX SBOM,
and publishes everything as a GitHub Release.

The workflow resolves the release body in priority order (see the
`Resolve release notes` step in `release.yaml`):

1. The **`CHANGELOG.md`** section whose heading matches
   `## [<version>] - <date>`, if present.
2. The **annotated tag message** (`git tag -a` subject + body, minus
   the signature) when there's no matching CHANGELOG section.
3. GitHub auto-generated notes — last resort if both are empty.

In current practice the annotated tag message (2) is the common path:
recent releases carry their notes in the `git tag -a` body rather than a
CHANGELOG bump, so the workflow falls through to it. Either way the notes
live in git (a committed CHANGELOG section or the annotated tag object),
are reviewable, and don't depend on commit-message hygiene. The shape
below applies to whichever you use.

## Pattern

Every release's notes — in a CHANGELOG section or the annotated tag
body — follow this shape:

```markdown
## [X.Y.Z] - YYYY-MM-DD

One-paragraph theme sentence — what changed at a high level and why
it matters to operators.

### Added
- New tools, capabilities, packages. Each bullet names the tool or
  package first, then what it does, then (when relevant) what
  operator intent it addresses.

### Changed
- Behavioural shifts that aren't fixes — e.g. a tool's default
  timeout changed, a verifier prompt got stricter, a risk tier moved.

### Fixed
- Bugs closed this release. Prefer "problem → fix" phrasing:
  "NFC scanner returned immediately instead of waiting for the
   card → now loops the subcommand until detection or timeout."

### Verified
- The green-bar evidence for this release:
  - `task test:full` result
  - `task eval` scenario count (N/N)
  - `golangci-lint run ./...` status
  - Live-Flipper validator counts: `pass=X fail=Y skip=Z`

### Deprecated / Removed / Security
Only include when applicable.
```

### Why this shape

- **Theme sentence first** so the release overview in the GitHub UI
  is readable at a glance without expanding sections.
- **Added / Changed / Fixed** mirrors [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
  — operators already know how to skim it.
- **Verified** block is PromptZero-specific. It's proof the release
  is safe to adopt, not just a list of shipped bullets. Every release
  must carry these four datapoints.
- **Operator-intent framing** in Added entries reduces the "what tool
  do I reach for?" problem — e.g. `nfc_read_save` entry explicitly
  says "the missing 'scan this fob' tool" so operators searching the
  release notes find it quickly.

## Pre-release checklist

Run from a clean working tree on `main`:

```sh
# 1. Fast tests + lint.
task test:full
golangci-lint run ./...

# 2. Eval harness.
task eval

# 3. Live-Flipper validator (only when the Flipper is connected and
#    the scenario under test matches the release's claims).
go build -o /tmp/flipper-validate ./cmd/flipper-validate
/tmp/flipper-validate -skip-reboot

# 4. Write the release notes in the shape above, with the Verified
#    block populated from steps 1-3. Put them EITHER in a new
#    CHANGELOG.md [X.Y.Z] - YYYY-MM-DD section (committed as
#    "docs: release notes for vX.Y.Z"), OR — the common path — directly
#    in the annotated tag body in step 5. The workflow reads CHANGELOG
#    first, then the tag body.

# 5. Tag + push. Carry the notes in the annotated tag body via a file
#    (-F) so multi-line notes survive and no shell interpolation mangles
#    them — avoid backticks in -m, the shell command-substitutes them.
git tag -a vX.Y.Z -F dist/release-notes.md   # or: git tag -a vX.Y.Z (opens $EDITOR)
git push origin vX.Y.Z
```

Verify the published notes afterwards with `gh release view vX.Y.Z`.

The tag push triggers `.github/workflows/release.yaml`:
1. Build five platform binaries (linux/amd64+arm64, darwin/amd64+arm64, windows/amd64)
2. Generate `checksums.txt`, sign with cosign keyless
3. Generate CycloneDX SBOM (`promptzero.cdx.json`)
4. Resolve the release notes: CHANGELOG section matching the tag →
   annotated tag body → auto-generated notes (so forgetting to bump
   CHANGELOG doesn't block the release; the tag body carries the notes)
5. Publish the GitHub Release with every artefact attached

## Versioning

PromptZero follows semver:

- **MAJOR** — removing or renaming a tool, breaking an audit-log
  schema, changing the persona YAML shape.
- **MINOR** — new tool categories (NRF24 toolkit, new workflow
  composite), new quality layers (Batch A–G), new eval scenarios.
- **PATCH** — bug fixes, cheat-sheet updates, verifier prompt
  tightening, pure docs changes.

Operator-facing tool descriptions are part of the public API —
changing them meaningfully counts as at least MINOR. Cosmetic
wording tweaks are PATCH.

## Writing good release notes

### Do

- Lead with the problem when describing a fix. `"NFC scanner
  returned success=true without saving a file → agent thrashed"`
  lands better than `"Fixed NFC bug"`.
- Include file-level call-outs for fixes that affected operator
  runs. Operators reading the notes want to know which tool calls
  will behave differently after upgrading.
- Keep the Verified block honest. If a live-Flipper validator run
  wasn't done for this release, say "hardware validator not re-run
  this release — tests + eval only." Don't claim coverage you
  didn't exercise.

### Don't

- List every commit SHA. The CHANGELOG is for humans; GitHub
  auto-generated notes have the commit list for anyone who wants it.
- Mix fixes into Added. A new tool that wasn't there before is
  Added; a broken tool now working is Fixed.
- Write release notes after-the-fact from `git log`. Good CHANGELOG
  entries are accumulated as the work lands — each PR appends to
  `[Unreleased]`, and the release step just renames the section.

## Hot-fix releases

For a PATCH that addresses a live incident:

```sh
# Branch from the most recent release tag.
git checkout -b hotfix/vX.Y.(Z+1) vX.Y.Z
# Cherry-pick the fix.
git cherry-pick <sha>
# Bump CHANGELOG's [X.Y.(Z+1)] section, commit.
# Tag and push.
git tag -a vX.Y.(Z+1) -m "vX.Y.(Z+1)"
git push origin vX.Y.(Z+1)
```

The workflow will build and release from the hotfix branch's tag;
when ready, merge the hotfix branch into `main` so future releases
include the fix.

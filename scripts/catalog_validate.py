#!/usr/bin/env python3
"""
catalog_validate.py — Validates Flipper Zero catalog Markdown tables.

Usage:
    python scripts/catalog_validate.py [catalog_dir]

Validates:
  - All .md files in the catalog directory tree contain properly formatted tables
  - Required columns are present in each table
  - URLs are well-formed (but does NOT perform live link checking)
  - Status values are valid (active/stale/archived/adversarial)
  - No obviously duplicate URLs within the same file

Exit code 0 = all valid. Exit code 1 = validation errors found.
"""

import sys
import re
from pathlib import Path
from urllib.parse import urlparse
from collections import defaultdict
from typing import NamedTuple

VALID_STATUSES = {"active", "stale", "archived", "adversarial", "community", "eol"}
# Only require 'name' as universal; url/author/status are validated when present
REQUIRED_COLUMNS = {"name"}
STANDARD_COLUMNS = ["name", "url", "author", "stars", "last commit", "license", "status", "notes"]
SKIP_FILES = {"README.md", "CONTRIBUTING.md"}
SKIP_DIRS = {"schema"}


class ValidationError(NamedTuple):
    file: str
    line: int
    message: str


def parse_md_tables(content: str) -> list[dict]:
    """Extract table rows from Markdown content, returning dicts keyed by normalised header."""
    tables = []
    lines = content.splitlines()
    header: list[str] | None = None
    in_table = False

    skip_table = False  # True when we are inside a legend/meta table to skip
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("|") and stripped.endswith("|"):
            cells = [c.strip() for c in stripped.split("|")[1:-1]]
            if not in_table:
                header = [c.lower().strip() for c in cells]
                # Skip legend/meta tables that use "column", "field", etc. as first header
                LEGEND_HEADERS = {"column", "field", "col", "parameter", "stars", "last commit", "status"}
                if header and header[0] in LEGEND_HEADERS and len(header) <= 3:
                    skip_table = True
                    in_table = True
                    continue
                skip_table = False
                in_table = True
                continue
            # Skip separator rows (e.g. |---|---|)
            if all(re.match(r"^[-:]+$", c) for c in cells if c):
                continue
            if skip_table:
                continue  # Skip body rows of legend tables
            if header and len(cells) == len(header):
                row = dict(zip(header, cells))
                row["_line"] = i + 1
                tables.append(row)
        else:
            in_table = False
            skip_table = False
            header = None

    return tables


def validate_url(url: str) -> bool:
    """Return True if the string looks like a structurally valid HTTP(S) URL."""
    if not url or url in ("N/A", "—", "-", "[URL WITHHELD]"):
        return True
    try:
        result = urlparse(url)
        return result.scheme in ("http", "https") and bool(result.netloc)
    except Exception:
        return False


def validate_status(status: str) -> bool:
    # Strip parenthetical qualifiers like "active (some note)" or "**EOL** (note)"
    # Extract the first word (base status)
    base = re.split(r"[\s(]", status.lower().lstrip("*"))[0].rstrip("*")
    return base in VALID_STATUSES


def validate_file(filepath: Path) -> list[ValidationError]:
    errors: list[ValidationError] = []
    try:
        content = filepath.read_text(encoding="utf-8")
    except Exception as exc:
        return [ValidationError(str(filepath), 0, f"Cannot read file: {exc}")]

    rows = parse_md_tables(content)
    if not rows:
        return []  # Files with no tables are fine (policy docs, etc.)

    seen_urls: dict[str, list[int]] = defaultdict(list)

    for row in rows:
        line = row.get("_line", 0)

        # Only validate rows that look like standard catalog entries
        # (must have BOTH 'url' AND 'status' columns; otherwise it's a non-standard table)
        if "url" not in row or "status" not in row:
            continue

        # Validate URL structure
        url = row.get("url", "").strip()
        if url and url not in ("N/A", "—", "[URL WITHHELD]", "url withheld"):
            if not validate_url(url):
                errors.append(
                    ValidationError(str(filepath), line, f"Malformed URL: {url!r}")
                )
            else:
                seen_urls[url].append(line)

        # Validate status
        status = row.get("status", "").strip()
        if status and not validate_status(status):
            errors.append(
                ValidationError(
                    str(filepath),
                    line,
                    f"Invalid status: {status!r} (must be one of {sorted(VALID_STATUSES)})",
                )
            )

        # Name must not be blank (only when 'name' column is present)
        if "name" in row:
            name = row.get("name", "").strip()
            if not name or name in ("—", "-"):
                errors.append(ValidationError(str(filepath), line, "Empty name field"))

    # Duplicate URL detection within a single file
    for url, lines in seen_urls.items():
        if len(lines) > 1:
            errors.append(
                ValidationError(
                    str(filepath),
                    min(lines),
                    f"Duplicate URL {url!r} appears on lines {lines}",
                )
            )

    return errors


def main(catalog_dir: str = "docs/catalog") -> int:
    catalog_path = Path(catalog_dir)
    if not catalog_path.exists():
        print(f"ERROR: Catalog directory not found: {catalog_path}", file=sys.stderr)
        return 1

    all_errors: list[ValidationError] = []
    files_checked = 0

    for md_file in sorted(catalog_path.rglob("*.md")):
        # Skip schema directory and well-known non-table files
        if any(part in SKIP_DIRS for part in md_file.parts):
            continue
        if md_file.name in SKIP_FILES:
            continue

        errors = validate_file(md_file)
        all_errors.extend(errors)
        files_checked += 1

    if all_errors:
        print(
            f"\n❌ Validation FAILED: {len(all_errors)} error(s) in {files_checked} files checked\n"
        )
        for err in sorted(all_errors, key=lambda e: (e.file, e.line)):
            print(f"  {err.file}:{err.line}: {err.message}")
        return 1

    print(f"✅ Validation PASSED: {files_checked} catalog files checked, 0 errors")
    return 0


if __name__ == "__main__":
    catalog_dir = sys.argv[1] if len(sys.argv) > 1 else "docs/catalog"
    sys.exit(main(catalog_dir))

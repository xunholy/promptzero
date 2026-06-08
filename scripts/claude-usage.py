#!/usr/bin/env python3
# claude-usage.py — aggregate this machine's local Claude Code session
# transcripts for this repo and emit a shields.io endpoint badge JSON.
#
# Claude usage/cost is stored only in the local CLI transcripts
# (~/.claude/projects/<slug>/*.jsonl); there is no public API a live badge can
# query. So this is a maintainer tool: run it (task claude-usage) to refresh
# .github/claude-usage.json, then commit. The badge therefore reflects THIS
# machine's sessions only and the cost is an estimate at the pricing below.
#
# Usage: python3 scripts/claude-usage.py [--repo <path>] [--out <json>]

import argparse
import glob
import json
import os
import sys

# Documented Anthropic pricing, USD per million tokens, per family:
# (input, output, cache-write 5m, cache-read).
PRICING = {
    "opus": (15.0, 75.0, 18.75, 1.50),
    "sonnet": (3.0, 15.0, 3.75, 0.30),
    "haiku": (1.0, 5.0, 1.25, 0.10),
}


def family(model: str):
    m = (model or "").lower()
    for fam in ("opus", "sonnet", "haiku"):
        if fam in m:
            return fam
    return None


def slug_for(repo_path: str) -> str:
    # Claude Code names the project dir after the absolute path with every
    # separator replaced by a dash.
    return os.path.abspath(repo_path).replace(os.sep, "-")


def human_tokens(n: int) -> str:
    if n >= 1_000_000_000:
        return f"{n / 1e9:.1f}B"
    if n >= 1_000_000:
        return f"{n / 1e6:.0f}M"
    return str(n)


def human_cost(usd: float) -> str:
    if usd >= 1000:
        return f"~${usd / 1000:.0f}k"
    return f"~${usd:.0f}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=os.getcwd())
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    proj = os.path.join(os.path.expanduser("~/.claude/projects"), slug_for(args.repo))
    files = glob.glob(os.path.join(proj, "*.jsonl"))
    if not files:
        print(f"no transcripts under {proj}", file=sys.stderr)
        return 1

    agg = {}  # family -> [input, output, cache_write, cache_read]
    sessions = len(files)
    for path in files:
        with open(path, errors="ignore") as fh:
            for line in fh:
                if '"usage"' not in line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                msg = obj.get("message", obj)
                if not isinstance(msg, dict):
                    continue
                usage = msg.get("usage")
                fam = family(msg.get("model"))
                if not usage or not fam:
                    continue
                a = agg.setdefault(fam, [0, 0, 0, 0])
                a[0] += usage.get("input_tokens", 0) or 0
                a[1] += usage.get("output_tokens", 0) or 0
                a[2] += usage.get("cache_creation_input_tokens", 0) or 0
                a[3] += usage.get("cache_read_input_tokens", 0) or 0

    total_tokens = 0
    total_cost = 0.0
    for fam, (i, o, cw, cr) in sorted(agg.items()):
        pi, po, pcw, pcr = PRICING[fam]
        cost = (i * pi + o * po + cw * pcw + cr * pcr) / 1e6
        total_cost += cost
        total_tokens += i + o + cw + cr
        print(f"{fam:7} tokens={human_tokens(i + o + cw + cr):>7}  est ${cost:,.2f}")

    message = f"{human_tokens(total_tokens)} tok · {human_cost(total_cost)}"
    print(f"\nsessions={sessions}  total={human_tokens(total_tokens)} tok  est ${total_cost:,.2f}")

    badge = {
        "schemaVersion": 1,
        "label": "claude",
        "message": message,
        "color": "D97757",  # Claude coral
    }
    out = args.out or os.path.join(args.repo, ".github", "claude-usage.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as fh:
        json.dump(badge, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    print(f"wrote {out}: {message}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

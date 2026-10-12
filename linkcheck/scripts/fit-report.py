#!/usr/bin/env python3
"""Cut a linkcheck report to a byte budget: whole rows, the worst first.

Usage:
    fit-report.py <room> < report

The report starts at its `=== link check` summary line, as both action.yml steps
cut it with awk. Prints how many rows it left out on the first line, then the
report cut to at most <room> bytes:

  * the summary line;
  * as many WHOLE rows as fit — a row is its `  [code] url` line and the
    `      on: …` line under it — each section's under its title, FATAL first,
    then REVIEW, then WARN (the report prints WARN first, and a flood of flaky
    externals must not crowd out the broken links);
  * the report's closing lines, from its verdict (`link check: …`) on. Room is
    kept for them before any row: on a collapsed crawl they carry the notice
    that the verdict is void, which a cut summary must not lose.

It counts bytes, which are never fewer than characters, so a Greek URL only
makes a cut stricter. It runs only on a report that does not fit: under the cap
both steps post the report as before, byte for byte.

Called by the crawl step (the step summary, 900,000 bytes: GitHub refuses one
over 1 MiB) and the issue step (the issue body, 60,000 bytes: GitHub refuses one
over 65,536 characters). Both reserve the room for the wrapper and the
"(truncated — N more rows; …)" note they add around it.

# lint-allow-no-crash-guard: a formatter, not a gate. It runs after the crawl
# step has published its verdict and decides nothing, so a fault here costs only
# the text it would have produced: the crawl step's `if` turns it into a
# ::warning:: and writes no summary, keeping the step's own exit code; the issue
# step (continue-on-error) posts nothing, as before v1.29.2. Neither can launder
# it into a verdict about the caller's links, and misattribution, not the exit
# code, is what rule 3 exists to catch.
"""
import sys

RANK = {b"FATAL": 0, b"REVIEW": 1, b"WARN": 2}


def cost(lines):
    """The bytes `lines` add after a line already out: a newline before each."""
    return sum(1 + len(x) for x in lines)


def fit(report, room):
    """(rows left out, the cut report) for `report` (bytes) in `room` bytes."""
    lines = report.rstrip(b"\n").split(b"\n")
    head, rest = lines[0], lines[1:]
    end = next((i for i, ln in enumerate(rest) if ln.startswith(b"link check: ")), len(rest))
    rest, tail = rest[:end], ([b""] + rest[end:] if end < len(rest) else [])
    blocks = []                                  # [title, [row, ...]]; a row is its lines
    for ln in rest:
        if not ln.strip():
            continue
        if not ln.startswith(b" "):              # a section title
            blocks.append([ln, []])
        elif ln.startswith(b"   ") and blocks and blocks[-1][1]:
            blocks[-1][1][-1].append(ln)         # "      on: ..." belongs to the row above
        else:
            if not blocks:
                blocks.append([None, []])
            blocks[-1][1].append([ln])           # "  [404] <url>" starts a row
    blocks.sort(key=lambda b: RANK.get((b[0] or b"").split(b" ")[0], 3))
    units = []                                   # (lines, 1 if a row), in posting order
    for title, rows in blocks:
        lead = [b""] + ([title] if title is not None else [])
        units += [((lead if i == 0 else []) + row, 1) for i, row in enumerate(rows)] or [(lead, 0)]
    if len(head) + cost(tail) > room:
        tail = []
    out, used, kept = [head], len(head) + cost(tail), 0
    for add, is_row in units:
        if used + cost(add) > room:
            break
        out += add
        used += cost(add)
        kept += is_row
    return sum(r for _, r in units) - kept, b"\n".join(out + tail)


def main():
    left_out, cut = fit(sys.stdin.buffer.read(), int(sys.argv[1]))
    sys.stdout.buffer.write(b"%d\n" % left_out + cut)


if __name__ == "__main__":
    main()

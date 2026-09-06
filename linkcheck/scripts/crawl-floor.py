#!/usr/bin/env python3
"""Judge THIS run's crawl size against the sizes of previous good runs.

Usage:
    crawl-floor.py decide --pages N --baseline FILE [--fraction F] [--min-history K]
    crawl-floor.py record --pages N --baseline FILE [--keep K]

`decide` prints ONE decision token on stdout — ok | collapsed | no-baseline |
unreadable — plus a human line on stderr, and always exits 0. It is a
DECISION, not a gate: action.yml owns what to do with it.

`record` appends N to the history and keeps the last K. Only ever called for a
run that produced a real verdict on a non-collapsed crawl, so a collapsed run
can never poison the median it is judged against.

WHY THIS EXISTS (2026-09-06, from creme-ypsilon/lampakia-astro run 33382684973)
------------------------------------------------------------------------------
That scheduled run reported `48 checked | 10 fatal` → FAIL, and named ten
`/katigoria/…` URLs as broken. The site was fine: every one of them returns 200,
and the next full run crawled 1824 pages / 5113 links with 0 fatal. What
actually happened is in the line above the verdict —

    Collected 18 page URLs across the sitemap          (the good run: 1824)

The page set had collapsed ~100x and NOTHING noticed. action.yml asserted
`[ "$N" -gt 0 ]`, which 18 satisfies. So the crawl faithfully checked 1% of the
site and the action published that as a verdict about the whole of it.

This is the fleet's `failed-probe-is-not-evidence` class. The three states are
PRESENT / ABSENT-WITH-EVIDENCE / COULD-NOT-LOOK, and collapsing the third into
the second is the defect: "we only saw 1% of the site" was reported as "these
links are broken".

AND THE DANGEROUS DIRECTION IS THE OTHER ONE. Had those 18 pages happened to be
link-clean, the verdict would have been `clean` — which CLOSES the broken-links
issue, declaring a site verified when 99% of it was never fetched. A collapsed
crawl must therefore invalidate BOTH verdicts, not just the red one. That
asymmetry is the whole reason this returns a decision rather than a boolean
"is it broken".

WHAT IT DELIBERATELY DOES NOT DO
--------------------------------
It does not fault a run it cannot judge. A caller with no history, an
unparseable baseline, or a crashed floor script keeps whatever verdict the crawl
produced — a size floor that red-lights every new caller is a gate that gets
switched off, and the protection is worth nothing then. Each of those states
prints its own line so "not judged" never renders as "healthy".

It measures COLLAPSE, not decay: the median moves with the site, so a site that
genuinely shrinks over weeks re-baselines instead of alarming forever.

The specific 2026-08-31 trigger was never recovered — the retained logs carry
the counts but not the sitemap body, and there was no deploy in the window. That
does not matter to the design. Nothing inside a single run can distinguish "this
site has 18 pages" from "we saw 18 of 1824"; only the site's own history can,
which is exactly what this file is.
"""
import argparse
import json
import os
import sys

# A 2x drop. The incident was 100x, so this is a wide margin against false
# positives while still catching anything that would invalidate a verdict.
# Overridable per caller via action.yml's `crawl-floor-fraction`.
DEFAULT_FRACTION = 0.5

# Three good runs before the floor is armed. Two would let a single outlier be
# half the median; three is the smallest set with a meaningful one.
DEFAULT_MIN_HISTORY = 3

# Keep a quarter of a year of weekly runs. Long enough that one bad-but-passing
# week cannot swing the median, short enough to track a growing site.
DEFAULT_KEEP = 13


def _median(xs):
    s = sorted(xs)
    n = len(s)
    return s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2


def load_history(path):
    """Return (history, state). state is 'ok' | 'missing' | 'unreadable'.

    Anything that is not a list of positive ints is `unreadable` rather than an
    exception: a corrupt cache entry must not be able to take a caller's gate
    down, and it must not silently read as an empty history either — those two
    are different facts and the report says which one it is.
    """
    if not path or not os.path.exists(path):
        return [], "missing"
    try:
        with open(path, encoding="utf-8") as f:
            raw = json.load(f)
    except Exception:  # noqa: BLE001 — a corrupt baseline is a state, not a crash
        return [], "unreadable"
    if not isinstance(raw, list):
        return [], "unreadable"
    hist = [v for v in raw if isinstance(v, int) and not isinstance(v, bool) and v > 0]
    if len(hist) != len(raw):
        return [], "unreadable"
    return hist, "ok"


def decide(pages, history, state, fraction=DEFAULT_FRACTION,
           min_history=DEFAULT_MIN_HISTORY):
    """Pure. Returns (decision, human_explanation)."""
    if state == "unreadable":
        return ("unreadable",
                "baseline file exists but is not a list of positive integers — "
                "the crawl size was NOT judged this run")
    if state == "missing":
        return ("no-baseline",
                "no baseline yet — the crawl size was NOT judged this run "
                "(the floor arms after %d good runs)" % min_history)
    if len(history) < min_history:
        return ("no-baseline",
                "baseline holds %d of the %d runs needed — the crawl size was "
                "NOT judged this run" % (len(history), min_history))
    med = _median(history)
    floor = fraction * med
    if pages < floor:
        return ("collapsed",
                "crawled %d pages against a %d-run median of %g — below the "
                "%gx floor of %.4g. The page set collapsed; this run saw "
                "a fraction of the site." % (pages, len(history), med, fraction, floor))
    return ("ok",
            "crawled %d pages against a %d-run median of %g (floor %.4g)"
            % (pages, len(history), med, floor))


def cmd_decide(args):
    hist, state = load_history(args.baseline)
    decision, why = decide(args.pages, hist, state,
                           fraction=args.fraction, min_history=args.min_history)
    print(f"crawl-floor: {decision} — {why}", file=sys.stderr)
    print(decision)
    return 0


def cmd_record(args):
    hist, state = load_history(args.baseline)
    if state == "unreadable":
        # Start over rather than refuse. The alternative is a caller whose floor
        # is permanently disarmed by one corrupt write with nothing to clear it.
        print("crawl-floor: baseline was unreadable — starting a fresh history",
              file=sys.stderr)
        hist = []
    hist.append(args.pages)
    hist = hist[-args.keep:]
    with open(args.baseline, "w", encoding="utf-8") as f:
        json.dump(hist, f)
    print(f"crawl-floor: recorded {args.pages} (history now {len(hist)} runs: {hist})",
          file=sys.stderr)
    return 0


def main():
    ap = argparse.ArgumentParser(prog="crawl-floor.py")
    sub = ap.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("decide")
    d.add_argument("--pages", type=int, required=True)
    d.add_argument("--baseline", required=True)
    d.add_argument("--fraction", type=float, default=DEFAULT_FRACTION)
    d.add_argument("--min-history", type=int, default=DEFAULT_MIN_HISTORY)
    d.set_defaults(fn=cmd_decide)

    r = sub.add_parser("record")
    r.add_argument("--pages", type=int, required=True)
    r.add_argument("--baseline", required=True)
    r.add_argument("--keep", type=int, default=DEFAULT_KEEP)
    r.set_defaults(fn=cmd_record)

    args = ap.parse_args()
    sys.exit(args.fn(args))


if __name__ == "__main__":
    # ---- crash guard ----
    # This is a GUARD, not a verdict, and the two fail in opposite directions.
    # linkcheck.py exits 2 on a crash because a crawler that died produced no
    # link verdict and must not be read as one. A floor script that dies has cost
    # us the extra protection, nothing more — the crawl's own verdict is still
    # whatever it was. Red-lighting every caller because this file threw would
    # take a working gate down over a broken guard, which is strictly worse than
    # the exposure it removes.
    #
    # So a crash degrades to `unreadable` on stdout and exit 0: action.yml reads
    # the same "was NOT judged" branch it uses for a caller with no history, and
    # the traceback goes to stderr for the run log. The one thing that must never
    # happen is a crash rendering as `ok` — hence the explicit print, rather than
    # letting the caller default an empty read to something.
    try:
        main()
    except SystemExit:
        raise
    except Exception:  # noqa: BLE001 — deliberate catch-all; re-reported, not swallowed
        import traceback
        sys.stderr.write(traceback.format_exc())
        sys.stderr.write("crawl-floor: CRASHED — the crawl size was NOT judged "
                         "this run; the crawl's own verdict stands\n")
        print("unreadable")
        sys.exit(0)

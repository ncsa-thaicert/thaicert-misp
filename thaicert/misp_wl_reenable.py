#!/var/www/MISP/venv/bin/python3
"""
MISP Warninglist Re-enable
==========================
Undo past auto-flagging by misp_warninglist_check.py for attributes that the
CURRENT matcher no longer considers a warninglist hit — mainly hosts created
by users on shared platforms (e.g. evil-login.netlify.app, phish.uk.com) and
URLs that used to be matched on their path.

Candidates come from the checker's own CSV reports (rows it applied,
"SET to_ids=False"), pre-filtered locally with the current
LocalWarninglistMatcher, then fetched live from MISP by uuid (indexed lookup,
500 per request) and kept only if still to_ids=False with the checker's
comment "[Auto] IDS disabled by warninglist checker". The final decision is
made on the live, untruncated value.
(Searching MISP by the audit tag instead takes minutes per page.)

Each candidate is classified:
  user_content — host created on a USER_CONTENT_PARENTS platform
  url_host     — URL previously matched on its path/query, host is not listed
  other        — no longer matched for another reason (e.g. list content changed)

Usage:
    ./misp_wl_reenable.py                       # dry-run, writes CSV report
    ./misp_wl_reenable.py --commit              # re-enable user_content + url_host
    ./misp_wl_reenable.py --commit --reasons user_content,url_host,other
"""

import argparse
import csv
import logging
import re
import sys
import time
from collections import Counter
from datetime import datetime

import misp_warninglist_check as wl

AUDIT_MARKER   = "[Auto] IDS disabled by warninglist checker"
_DISABLED_NOTE = re.compile(r"(?:\s\|\s)?\[Auto\] IDS disabled by warninglist checker\. Matched: [^|]*?(?=\s\|\s|$)")
REASONS        = ("user_content", "url_host", "other")

# Reuse the checker's logger/format but write to this script's own log file
log = wl.logger
log.handlers.clear()
for h in (logging.StreamHandler(), logging.FileHandler(wl.SCRIPT_DIR / "misp_wl_reenable.log", encoding="utf-8")):
    h.setFormatter(wl._fmt)
    log.addHandler(h)


def user_content_parent(value: str) -> str | None:
    """Platform the host was created under, or None (same host parsing as the matcher)."""
    host = wl._URL_SCHEME.sub("", value.lower(), count=1)
    host = wl._HOST_END.split(host, maxsplit=1)[0].rsplit("@", 1)[-1]
    if host.count(":") == 1:
        host = host.split(":")[0]
    labels = host.rstrip(".").split(".")
    for i in range(1, len(labels)):
        suffix = ".".join(labels[i:])
        if suffix in wl.USER_CONTENT_PARENTS and not (i == 1 and labels[0] == "www"):
            return suffix
    return None


def restore_comment(comment: str) -> str:
    """Comment as it was before the checker appended its note."""
    restored = _DISABLED_NOTE.sub("", comment).strip()
    return restored[1:].lstrip() if restored.startswith("|") else restored


def clean_hash_cut_unverifiable(comment: str, matcher) -> bool:
    """Disabled because of clean-hash feed, but the clean-hash store is unavailable to re-check it."""
    return not matcher.clean_hash_enabled and f"{wl.CLEAN_HASH_LIST_NAME} (" in comment


def load_report_candidates(matcher) -> dict[str, dict]:
    """uuid -> CSV row, for attributes the checker disabled and would no longer flag."""
    cands, applied = {}, 0
    for f in sorted(wl.SCRIPT_DIR.glob("misp_wl_report_*.csv")):
        with open(f, encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                if r.get("action") != "SET to_ids=False":
                    continue
                applied += 1
                value = r["attribute_value"]
                # report values are cut at 120 chars: let the live value decide
                if len(value) >= 120 or not matcher.match(value, r.get("attribute_type", "")):
                    cands[r["attribute_uuid"]] = r
    log.info(f"CSV reports: {applied:,} applied row(s), {len(cands):,} unique candidate(s) after local re-check")
    return cands


def fetch_live(misp, cfg, uuids: list[str], batch_size: int = 500) -> list[dict]:
    """Current state of the given attributes, looked up by uuid."""
    out = []
    for i in range(0, len(uuids), batch_size):
        chunk = uuids[i:i + batch_size]
        res = wl.with_retry(
            lambda c=chunk: misp.search(controller="attributes", uuid=c,
                                        limit=len(c), pythonify=False),
            cfg["retry_attempts"], cfg["retry_delay"], f"uuid-batch-{i // batch_size + 1}",
        )
        out.extend(res.get("Attribute", []) if isinstance(res, dict) else (res or []))
        if (i // batch_size) % 10 == 0:
            log.info(f"  Fetched {min(i + batch_size, len(uuids)):,}/{len(uuids):,}")
    return out


def main():
    p = argparse.ArgumentParser(description="Re-enable to_ids for attributes the warninglist checker no longer flags")
    p.add_argument("--config", default=str(wl.DEFAULT_CONFIG))
    p.add_argument("--commit", action="store_true", help="Apply changes (default: dry-run)")
    p.add_argument("--reasons", default="user_content,url_host",
                   help=f"Comma-separated reasons to re-enable with --commit (choices: {','.join(REASONS)})")
    p.add_argument("--exclude-keywords", default=",".join(wl.DEFAULT_EXCLUDE_KEYWORDS))
    p.add_argument("--publish-delay", type=float, default=2.0,
                   help="Seconds to wait between event publishes (default: 2)")
    args = p.parse_args()

    reasons = {r.strip() for r in args.reasons.split(",") if r.strip()}
    if not reasons <= set(REASONS):
        p.error(f"--reasons must be from {REASONS}")

    log.info(f"Mode: {'COMMIT' if args.commit else 'DRY-RUN'}  reasons={sorted(reasons)}")
    cfg     = wl.load_config(args.config)
    misp    = wl.connect_misp(cfg)
    matcher = wl.LocalWarninglistMatcher(
        wl.get_enabled_warninglist_names(misp),
        [k.strip() for k in args.exclude_keywords.split(",") if k.strip()],
        clean_hash=wl.open_clean_hash(),
    )

    cands = load_report_candidates(matcher)
    log.info(f"Fetching current state of {len(cands):,} attribute(s) from MISP by uuid ...")
    live  = fetch_live(misp, cfg, list(cands))

    rows, counts = [], Counter()
    full_comments = {}   # uuid -> untruncated comment (CSV keeps only 300 chars)
    counts["skip: deleted / not found"] = len(cands) - len(live)
    for a in live:
        comment = a.get("comment") or ""
        if a.get("to_ids") in (True, 1, "1"):
            counts["skip: to_ids already True"] += 1
            continue
        if AUDIT_MARKER not in comment:
            counts["skip: no checker comment"] += 1
            continue
        if clean_hash_cut_unverifiable(comment, matcher):
            counts["keep disabled: clean-hash store unavailable"] += 1
            continue
        value = str(a.get("value", "")).strip()
        hits  = matcher.match(value, a.get("type", ""))
        if hits:
            counts["keep disabled: still matched"] += 1
            continue
        parent = user_content_parent(value)
        reason = "user_content" if parent else ("url_host" if a.get("type") == "url" else "other")
        counts[f"re-enable candidate: {reason}"] += 1
        selected = reason in reasons
        full_comments[a.get("uuid")] = comment
        rows.append({
            "event_id":       str(a.get("event_id")),
            "attribute_id":   str(a.get("id")),
            "attribute_uuid": a.get("uuid"),
            "attribute_type": a.get("type"),
            "attribute_value": value[:200],
            "reason":         reason,
            "platform":       parent or "",
            "old_comment":    comment[:300],
            "action":         ("SET to_ids=True" if args.commit else "WOULD SET to_ids=True") if selected else "not selected",
        })

    selected_rows = [r for r in rows if r["action"] != "not selected"]
    events        = sorted({r["event_id"] for r in selected_rows}, key=int)

    # ── Apply ────────────────────────────────────────────────────────────
    updated, failed, published, untag_failed = 0, 0, 0, 0
    if args.commit:
        for i, r in enumerate(selected_rows, 1):
            payload  = {"id": r["attribute_id"], "uuid": r["attribute_uuid"], "to_ids": True,
                        "comment": restore_comment(full_comments[r["attribute_uuid"]])}
            try:
                wl.with_retry(lambda pl=payload: misp.update_attribute(pl),
                              cfg["retry_attempts"], cfg["retry_delay"], f"update-{r['attribute_id']}")
                try:
                    misp.untag(r["attribute_uuid"], wl.AUDIT_TAG)
                except Exception as exc:
                    untag_failed += 1
                    log.warning(f"  untag attr {r['attribute_id']}: {exc}")
                updated += 1
                if i % 1000 == 0:
                    log.info(f"  Updated {i:,}/{len(selected_rows):,}")
            except Exception as exc:
                failed += 1
                r["action"] = f"FAILED: {exc}"
                log.error(f"  ✗ attr {r['attribute_id']}: {exc}")
        done_events = sorted({r["event_id"] for r in selected_rows if r["action"].startswith("SET")}, key=int)
        log.info(f"Publishing {len(done_events)} event(s), {args.publish_delay}s apart ...")
        for eid in done_events:
            try:
                wl.with_retry(lambda e=eid: misp.publish(e, alert=False),
                              cfg["retry_attempts"], cfg["retry_delay"], f"publish-{eid}")
                published += 1
            except Exception as exc:
                log.error(f"  ✗ publish event {eid}: {exc}")
            time.sleep(args.publish_delay)

    # ── Report ───────────────────────────────────────────────────────────
    ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = wl.SCRIPT_DIR / f"misp_wl_reenable_{'commit' if args.commit else 'dryrun'}_{ts}.csv"
    if rows:
        with open(out, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)

    log.info("=" * 70)
    log.info(f"Candidates checked live: {len(live):,}")
    for k, v in sorted(counts.items()):
        log.info(f"  {k:<40}: {v:,}")
    log.info(f"Selected for re-enable ({','.join(sorted(reasons))}): {len(selected_rows):,} "
             f"in {len(events):,} event(s)")
    by_platform = Counter(r["platform"] for r in selected_rows if r["platform"])
    if by_platform:
        log.info("  Top platforms: " + ", ".join(f"{p}={n}" for p, n in by_platform.most_common(10)))
    by_type = Counter(r["attribute_type"] for r in selected_rows)
    log.info("  By type      : " + ", ".join(f"{t}={n}" for t, n in by_type.most_common()))
    if args.commit:
        log.info(f"Updated: {updated:,}  Failed: {failed:,}  Untag failed: {untag_failed:,}  "
                 f"Events published: {published:,}")
    else:
        log.info("DRY-RUN — nothing changed. Re-run with --commit to apply.")
    if rows:
        log.info(f"CSV report: {out}")
    log.info("=" * 70)


if __name__ == "__main__":
    main()

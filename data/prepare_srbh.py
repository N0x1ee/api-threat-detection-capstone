"""Clean, label-map, de-duplicate and split SR-BH 2020 (SRS v1.1, Section 9).

    python data/prepare_srbh.py
    python data/prepare_srbh.py --input data/raw/srbh/data_capec_multilabel.csv --allow-partial

Standard library only. Streams the 436 MB CSV, so memory use stays low.

Output (data/processed/):
    srbh_clean.csv.gz     one row per unique request, with split and project class
    srbh_summary.json     counts for the report (also printed)

What it does
    1. Parses the 38-column CSV (24 request/response fields + 14 CAPEC label columns).
    2. Privacy (DATA-027, SEC-025): raw source/destination IPs are dropped. Only a salted
       hash of the source /24 is kept. Cookies are replaced by a hash.
    3. Maps the multi-label CAPEC columns to the project's classes (Table 5.1):
         normal       000 only
         sqli         66
         cmdi         88, 248, 242
         traversal    126
         bruteforce   16
         scanning     310
         other_attack 272, 153, 274, 194, 34, 33
       When several are set, the first in this order wins:
         sqli > cmdi > traversal > bruteforce > scanning > other_attack.
       All CAPEC ids are kept in the `capec` column for anyone who wants the raw labels.
    4. De-duplicates on (method, request, body, user agent, labels) (DATA-032).
    5. Splits per class in capture order (default, --split class_time): within each class the
       first 70% of unique requests are train, the next 15% validation, the last 15% test.
       Why not split by day (AI-062 as first written)? In the real file every attack falls on
       17-19 July 2020; the other 11 days are normal traffic only, so a day split leaves the
       validation and test sets with no attacks. `--split day` is kept for comparison.
"""
import argparse
import collections
import csv
import datetime as dt
import gzip
import hashlib
import json
import os
import sys
from urllib.parse import urlsplit

ROOT = os.path.dirname(os.path.abspath(__file__))
DEFAULT_IN = os.path.join(ROOT, "raw", "srbh", "data_capec_multilabel.csv")
OUT_DIR = os.path.join(ROOT, "processed")

N_FIELDS = 24
CLASS_ORDER = [
    ("sqli", {"66"}),
    ("cmdi", {"88", "248", "242"}),
    ("traversal", {"126"}),
    ("bruteforce", {"16"}),
    ("scanning", {"310"}),
    ("other_attack", {"272", "153", "274", "194", "34", "33"}),
]
OUT_COLS = [
    "id", "ts", "day", "split", "method", "path", "query", "protocol", "user_agent", "referer",
    "host", "origin", "cookie_hash", "content_type", "accept", "accept_language",
    "accept_encoding", "dnt", "connection", "body", "status", "resp_length",
    "src_net_hash", "identity", "capec", "label", "is_attack", "single_label",
]


def h(text, salt, n=16):
    return hashlib.sha256((salt + "|" + text).encode("utf-8", "ignore")).hexdigest()[:n] if text else ""


def parse_ts(s):
    return dt.datetime.strptime(s, "%d/%b/%Y:%H:%M:%S %z")


def primary_class(capec):
    if capec == ["000"] or not capec:
        return "normal"
    s = set(capec)
    for name, ids in CLASS_ORDER:
        if s & ids:
            return name
    return "other_attack"


def split_by_position(i, n):
    f = (i + 1) / n
    return "train" if f <= 0.70 else ("val" if f <= 0.85 else "test")


def dedupe_key(row, capec):
    return hashlib.sha1("\x1f".join([row[5], row[6], row[19].replace("\r\n", "\n"), row[8], ",".join(capec)])
                        .encode("utf-8", "ignore")).digest()


def split_for(day_rank, n_days):
    if n_days == 12:
        return "train" if day_rank <= 8 else ("val" if day_rank <= 10 else "test")
    f = day_rank / n_days
    return "train" if f <= 2 / 3 else ("val" if f <= 5 / 6 else "test")


def read_rows(path, allow_partial):
    csv.field_size_limit(min(sys.maxsize, 2**31 - 1))
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.reader(f)
        header = next(reader)
        if len(header) != N_FIELDS + 14:
            sys.exit(f"Expected 38 columns, found {len(header)}. Is this the SR-BH multilabel CSV?")
        capec_ids = [c.split(" - ")[0].strip() for c in header[N_FIELDS:]]
        bad = 0
        while True:
            try:
                row = next(reader)
            except StopIteration:
                break
            except csv.Error:
                if allow_partial:
                    break
                raise
            if len(row) != len(header):
                bad += 1
                continue
            yield header, capec_ids, row
        read_rows.bad = bad


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default=DEFAULT_IN)
    ap.add_argument("--split", choices=["class_time", "day"], default="class_time")
    ap.add_argument("--allow-partial", action="store_true", help="accept a truncated file (for testing)")
    ap.add_argument("--salt", default=os.environ.get("CAPSTONE_SALT", "capstone-srbh-v1"),
                    help="salt for IP/cookie hashing (set CAPSTONE_SALT to keep it out of the code)")
    args = ap.parse_args()
    if not os.path.exists(args.input) and os.path.exists(args.input + ".gz"):
        args.input += ".gz"           # accept data_capec_multilabel.csv.gz (e.g. from Colab/Drive)
    if not os.path.exists(args.input):
        sys.exit(f"Not found: {args.input}\nDownload SR-BH first (see data/README.md).")
    os.makedirs(OUT_DIR, exist_ok=True)

    # Pass 1: find the capture days so the split is known before writing.
    print("Pass 1/2: scanning days, classes and order ...")
    days = collections.Counter()
    class_total = collections.Counter()
    seen, last_ts, out_of_order = set(), None, 0
    for _, capec_ids, row in read_rows(args.input, args.allow_partial):
        try:
            ts = parse_ts(row[0])
        except ValueError:
            continue
        days[ts.date()] += 1
        if last_ts and ts < last_ts:
            out_of_order += 1
        last_ts = ts
        capec = [cid for cid, v in zip(capec_ids, row[N_FIELDS:]) if v.strip() == "1"]
        if not capec:
            continue
        k = dedupe_key(row, capec)
        if k not in seen:
            seen.add(k)
            class_total[primary_class(capec)] += 1
    seen = None
    ordered = sorted(days)
    rank = {d: i + 1 for i, d in enumerate(ordered)}
    print(f"  {len(ordered)} day(s): {ordered[0]} .. {ordered[-1]}" if ordered else "  no valid timestamps")

    # Pass 2: clean, map, dedupe, write.
    print("Pass 2/2: cleaning and writing ...")
    seen = set()
    class_pos = collections.Counter()
    stats = collections.Counter()
    by_split = collections.defaultdict(collections.Counter)
    capec_counts = collections.Counter()
    combos = collections.Counter()
    src_ips, user_agents = set(), set()
    out_path = os.path.join(OUT_DIR, "srbh_clean.csv.gz")
    with gzip.open(out_path, "wt", encoding="utf-8", newline="") as gz:
        w = csv.writer(gz)
        w.writerow(OUT_COLS)
        for _, capec_ids, row in read_rows(args.input, args.allow_partial):
            stats["rows_read"] += 1
            try:
                ts = parse_ts(row[0])
            except ValueError:
                stats["bad_timestamp"] += 1
                continue
            capec = [cid for cid, v in zip(capec_ids, row[N_FIELDS:]) if v.strip() == "1"]
            if not capec:
                stats["no_label"] += 1
                continue
            method, request, body, ua = row[5], row[6], row[19].replace("\r\n", "\n"), row[8]
            key = dedupe_key(row, capec)
            if key in seen:
                stats["duplicates_removed"] += 1
                continue
            seen.add(key)

            parts = urlsplit(request if request.startswith("/") else "/" + request)
            ip = row[1]
            src_ips.add(ip)
            user_agents.add(ua)
            net = ".".join(ip.split(".")[:3]) if ip.count(".") == 3 else ip
            cookie_hash = h(row[12], args.salt)
            label = primary_class(capec)
            is_attack = int(label != "normal")
            if args.split == "day":
                split = split_for(rank[ts.date()], len(ordered))
            else:
                split = split_by_position(class_pos[label], class_total[label])
                class_pos[label] += 1
            # identity for sequence building: source network + user agent + cookie
            identity = h(f"{net}|{ua}|{row[12]}", args.salt)
            stats["rows_written"] += 1
            by_split[split][label] += 1
            for cid in capec:
                capec_counts[cid] += 1
            combos[",".join(capec)] += 1
            w.writerow([
                stats["rows_written"], ts.isoformat(), rank[ts.date()], split, method, parts.path,
                parts.query, row[7], ua, row[9], row[10], row[11], cookie_hash, row[13], row[14],
                row[15], row[16], row[17], row[18], body, row[21], row[23],
                h(net, args.salt), identity, ";".join(capec), label, is_attack, int(len(capec) == 1),
            ])
            if stats["rows_written"] % 100000 == 0:
                print(f"  {stats['rows_written']:,} rows written")
    stats["malformed_rows_skipped"] = getattr(read_rows, "bad", 0)

    labels = [name for name, _ in CLASS_ORDER]
    labels.insert(0, "normal")
    summary = {
        "input": os.path.relpath(args.input, ROOT),
        "input_bytes": os.path.getsize(args.input),
        "split_method": args.split,
        "rows_out_of_time_order": out_of_order,
        "days": [str(d) for d in ordered],
        "rows_per_day": {str(d): days[d] for d in ordered},
        "stats": dict(stats),
        "distinct_source_ips": len(src_ips),
        "distinct_user_agents": len(user_agents),
        "split_by_class": {s: {l: by_split[s][l] for l in labels} for s in ("train", "val", "test")},
        "capec_counts": dict(capec_counts.most_common()),
        "top_label_combinations": dict(combos.most_common(15)),
        "class_mapping": {name: sorted(ids) for name, ids in CLASS_ORDER},
    }
    with open(os.path.join(OUT_DIR, "srbh_summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=1)

    print(f"\nWrote {out_path}")
    print(f"  read {stats['rows_read']:,} | duplicates removed {stats['duplicates_removed']:,} | "
          f"kept {stats['rows_written']:,} | malformed {stats['malformed_rows_skipped']:,}")
    print(f"  distinct source IPs: {len(src_ips)} | distinct user agents: {len(user_agents):,}")
    print(f"\n  {'class':<13}" + "".join(f"{s:>10}" for s in ("train", "val", "test")))
    for l in labels:
        print(f"  {l:<13}" + "".join(f"{by_split[s][l]:>10,}" for s in ("train", "val", "test")))


if __name__ == "__main__":
    main()

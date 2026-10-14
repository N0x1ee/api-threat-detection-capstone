"""Build the labelled payload corpus from data/seeds/ (dataset DS-3, feeds the generator DS-2).

    python data/build_payload_corpus.py

Output: data/processed/payloads.csv.gz  columns: payload, label, split, source
        data/processed/payloads_summary.json

- Classes: sqli, xss, cmdi, traversal (trainable) and ssti, ssrf (held out).
- Comment lines (#...), blank lines and lines over 2 000 chars are dropped.
- Exact duplicates are merged. A payload that appears under two different classes is
  dropped, because its label is ambiguous.
- Split is decided by a hash of the payload text, so it is stable between runs and a
  payload can never be in two splits: 70% train, 15% val, 15% test.
- Held-out classes get split = "heldout" and must never be used for training or tuning (AI-063).
"""
import collections
import csv
import gzip
import hashlib
import json
import os

ROOT = os.path.dirname(os.path.abspath(__file__))
SEEDS = os.path.join(ROOT, "seeds")
OUT = os.path.join(ROOT, "processed")
FOLDERS = {"sqli": "sqli", "xss": "xss", "cmdi": "cmdi", "traversal": "traversal",
           "ssti_heldout": "ssti", "ssrf_heldout": "ssrf"}
HELDOUT = {"ssti", "ssrf"}
MAX_LEN = 2000


def split_of(text):
    b = int(hashlib.sha1(text.encode("utf-8", "ignore")).hexdigest()[:8], 16) % 100
    return "train" if b < 70 else ("val" if b < 85 else "test")


def main():
    found = collections.defaultdict(set)      # payload -> labels
    source = {}
    dropped = collections.Counter()
    for folder, label in FOLDERS.items():
        for dirpath, _, files in os.walk(os.path.join(SEEDS, folder)):
            for name in sorted(files):
                if not name.endswith(".txt"):
                    continue
                path = os.path.join(dirpath, name)
                with open(path, encoding="utf-8", errors="replace") as f:
                    for line in f:
                        p = line.rstrip("\r\n")
                        if not p.strip():
                            dropped["blank"] += 1
                            continue
                        if p.lstrip().startswith("#") and label not in ("sqli", "cmdi"):
                            # '#' starts real payloads in SQL (comment) and shell; elsewhere it is a list comment
                            dropped["comment"] += 1
                            continue
                        if len(p) > MAX_LEN:
                            dropped["too_long"] += 1
                            continue
                        found[p].add(label)
                        source.setdefault((p, label), os.path.relpath(path, SEEDS).replace("\\", "/"))

    rows, ambiguous = [], 0
    for p, labels in found.items():
        if len(labels) > 1:
            ambiguous += 1
            continue
        label = next(iter(labels))
        rows.append((p, label, "heldout" if label in HELDOUT else split_of(p), source[(p, label)]))
    rows.sort(key=lambda r: (r[1], r[2], r[0]))

    os.makedirs(OUT, exist_ok=True)
    with gzip.open(os.path.join(OUT, "payloads.csv.gz"), "wt", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["payload", "label", "split", "source"])
        w.writerows(rows)

    table = collections.defaultdict(collections.Counter)
    for _, label, split, _ in rows:
        table[label][split] += 1
    summary = {"unique_payloads": len(rows), "dropped_ambiguous_cross_class": ambiguous,
               "dropped_lines": dict(dropped), "by_class_and_split": {k: dict(v) for k, v in sorted(table.items())}}
    with open(os.path.join(OUT, "payloads_summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=1)

    print(f"{len(rows):,} unique payloads ({ambiguous} ambiguous dropped)")
    print(f"{'class':<10}{'train':>8}{'val':>8}{'test':>8}{'heldout':>9}")
    for label in sorted(table):
        t = table[label]
        print(f"{label:<10}{t['train']:>8}{t['val']:>8}{t['test']:>8}{t['heldout']:>9}")


if __name__ == "__main__":
    main()

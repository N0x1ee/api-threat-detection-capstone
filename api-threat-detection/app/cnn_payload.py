"""Payload Agent, primary model: character-level CNN (SRS v1.1 AI-019 to AI-021).

Training uses Keras (train_cnn.py); inference here is pure NumPy from the exported weights,
so the agent containers do not need TensorFlow.

Input  : once-decoded path + query + body, at most 1 024 characters (AI-019).
Classes: benign, sqli, xss, cmdi, traversal. SSTI/SSRF are never trained on (held out).
Score  : 1 - P(benign).  Confidence (ADD-25): max softmax(logits / T), T fitted on validation.
Tokens : for the predicted class, the text windows where the most influential filters fired (AI-021).
"""
from urllib.parse import unquote_plus

import numpy as np

from .agents import AgentResult

CLASSES = ["benign", "sqli", "xss", "cmdi", "traversal"]
MAX_LEN = 1024
VOCAB = 98            # 0 = padding, 1 = other, 2..96 = printable ASCII 32..126, 97 = newline/tab


def cnn_text(req):
    path = (req.get("path") or req.get("endpoint") or "").split("?")[0]
    raw = " ".join(x for x in (path, req.get("query") or "", req.get("body") or "") if x)
    try:
        return unquote_plus(raw)[:MAX_LEN]
    except Exception:
        return raw[:MAX_LEN]


def encode(text, length=MAX_LEN):
    out = np.zeros(length, dtype=np.int32)
    for i, ch in enumerate(text[:length]):
        o = ord(ch)
        out[i] = o - 30 if 32 <= o <= 126 else (97 if ch in "\n\t\r" else 1)
    return out


def _softmax(z):
    z = z - z.max()
    e = np.exp(z)
    return e / e.sum()


class CNNPayloadAgent:
    name = "payload"
    model_name = "char_cnn"

    def __init__(self, weights_path):
        w = np.load(weights_path, allow_pickle=False)
        self.emb = w["embedding"]                                    # (VOCAB, d)
        self.convs = []
        i = 0
        while f"conv{i}_k" in w:
            self.convs.append((w[f"conv{i}_k"], w[f"conv{i}_b"]))   # k: (width, d, filters)
            i += 1
        self.d1_w, self.d1_b = w["dense1_k"], w["dense1_b"]
        self.out_w, self.out_b = w["out_k"], w["out_b"]
        self.T = float(w["temperature"])
        self.version = str(w["version"]) if "version" in w else "1"

    def forward(self, text):
        ids = encode(text, max(len(text), 8))
        x = self.emb[ids]                                            # (L, d)
        pooled, argmax, widths = [], [], []
        for k, b in self.convs:
            width = k.shape[0]
            L = x.shape[0]
            if L < width:
                x_ = np.vstack([x, np.zeros((width - L, x.shape[1]), x.dtype)])
            else:
                x_ = x
            win = np.lib.stride_tricks.sliding_window_view(x_, (width, x_.shape[1]))[:, 0]   # (L-w+1, w, d)
            h = np.maximum(np.tensordot(win, k, axes=([1, 2], [0, 1])) + b, 0)               # (L-w+1, F)
            pooled.append(h.max(0))
            argmax.append(h.argmax(0))
            widths.append(width)
        feat = np.concatenate(pooled)
        hid = np.maximum(feat @ self.d1_w + self.d1_b, 0)
        logits = hid @ self.out_w + self.out_b
        return logits, feat, hid, argmax, widths

    def _tokens(self, text, cls, feat, hid, argmax, widths, limit=4):
        """Filters ranked by their (linearised) push towards `cls`; return where they fired."""
        relevance = (self.d1_w * (hid > 0)) @ self.out_w[:, cls]          # d(logit_cls)/d(feat)
        contrib = feat * relevance
        offsets = np.cumsum([0] + [a.shape[0] for a in argmax])
        toks = []
        for j in np.argsort(-contrib)[:20]:
            if contrib[j] <= 0:
                break
            g = int(np.searchsorted(offsets, j, side="right") - 1)
            pos = int(argmax[g][j - offsets[g]])
            a, b = pos, min(len(text), pos + widths[g])
            while a > 0 and not text[a - 1].isspace() and pos - a < 12:
                a -= 1
            while b < len(text) and not text[b].isspace() and b - pos < 24:
                b += 1
            tok = text[a:b].strip()[:40]
            if tok and not any(tok in t or t in tok for t in toks):
                toks.append(tok)
            if len(toks) >= limit:
                break
        return toks

    def analyze(self, req):
        text = cnn_text(req)
        if not text.strip():
            return AgentResult(self.name, 0.0, 0.3, {"attack_type": "normal", "tokens": [], "reason": "",
                                                     "model": self.model_name})
        logits, feat, hid, argmax, widths = self.forward(text)
        p_raw = _softmax(logits)
        p = _softmax(logits / self.T)
        score = float(1.0 - p_raw[0])
        conf = float(p.max())
        cls = int(np.argmax(p_raw))
        detail = {"model": self.model_name, "probs": {c: round(float(v), 4) for c, v in zip(CLASSES, p_raw)}}
        if cls != 0 and score >= 0.5:
            atype = CLASSES[cls]
            toks = self._tokens(text, cls, feat, hid, argmax, widths)
            reason = f"Payload looks like {atype} ({score * 100:.0f}% sure)."
            if toks:
                reason += " Suspicious parts: " + ", ".join(f"`{t}`" for t in toks) + "."
            detail.update(attack_type=atype, tokens=toks, reason=reason)
        else:
            detail.update(attack_type="normal", tokens=[], reason="")
        return AgentResult(self.name, score, conf, detail)

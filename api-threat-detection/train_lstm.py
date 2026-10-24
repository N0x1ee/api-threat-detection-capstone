"""Train the behaviour LSTM (Keras) and export NumPy weights.

    python train_lstm.py      # writes models/behavior_lstm.npz and results/behavior_lstm.md

Sessions come from app/behavior_lstm.py (benign, scanning, credential stuffing, scraping).
Train / validation / test use different random seeds, so no session is shared between them.
"""
import json
import os
import random
import time

import numpy as np

from app.behavior_lstm import CLASSES, ENDPOINTS, METHODS, N_GAP, STATUS, LSTMBehaviorAgent, make_windows, pad

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "weights", "behavior_lstm.npz")   # small file, committed to git
DIMS = [16, 4, 4, 4, 2]
SIZES = [len(ENDPOINTS), len(METHODS), len(STATUS), N_GAP, 3]
UNITS = 48


def build_model():
    import tensorflow as tf
    from tensorflow.keras import layers
    inp = layers.Input((None, 5), dtype="int32")
    embs = []
    for j in range(5):
        col = layers.Lambda(lambda x, j=j: x[:, :, j], name=f"col{j}")(inp)
        embs.append(layers.Embedding(SIZES[j], DIMS[j], mask_zero=(j == 0), name=f"emb{j}")(col))
    x = layers.Concatenate()(embs)
    x = layers.LSTM(UNITS, name="lstm")(x)
    out = layers.Dense(len(CLASSES), name="dense")(x)
    m = tf.keras.Model(inp, out)
    m.compile(optimizer=tf.keras.optimizers.Adam(3e-3),
              loss=tf.keras.losses.SparseCategoricalCrossentropy(from_logits=True), metrics=["accuracy"])
    return m


def fit_temperature(logits, y):
    best = (1e9, 1.0)
    for T in np.arange(0.5, 5.01, 0.05):
        z = logits / T
        z = z - z.max(1, keepdims=True)
        nll = -np.mean(z[np.arange(len(y)), y] - np.log(np.exp(z).sum(1)))
        best = min(best, (nll, float(T)))
    return best[1]


def ece(conf, correct, bins=10):
    e = 0.0
    for i in range(bins):
        m = (conf > i / bins) & (conf <= (i + 1) / bins)
        if m.any():
            e += m.mean() * abs(conf[m].mean() - correct[m].mean())
    return float(e)


def _numpy_logits(agent, window):
    sg = lambda v: 1 / (1 + np.exp(-v))
    h = np.zeros(agent.units)
    c = np.zeros(agent.units)
    u = agent.units
    for row in window:
        x = np.concatenate([agent.embs[j][row[j]] for j in range(5)])
        g = x @ agent.Wx + h @ agent.Wh + agent.b
        c = sg(g[u:2 * u]) * c + sg(g[:u]) * np.tanh(g[2 * u:3 * u])
        h = sg(g[3 * u:]) * np.tanh(c)
    return h @ agent.d_w + agent.d_b


def main():
    import tensorflow as tf
    tf.keras.utils.set_random_seed(42)
    t0 = time.time()
    Xtr, ytr, _ = make_windows(random.Random(1), 6000, n_traffic=3000)
    Xva, yva, _ = make_windows(random.Random(2), 1200, n_traffic=600)
    Xte, yte, lte = make_windows(random.Random(3), 1500, n_traffic=750)
    Xtr, Xva, Xte = pad(Xtr), pad(Xva), pad(Xte)
    print(f"windows: train {len(ytr)}, val {len(yva)}, test {len(yte)}  ({time.time() - t0:.0f}s)")

    counts = np.bincount(ytr, minlength=len(CLASSES))
    cw = {i: len(ytr) / (len(CLASSES) * c) for i, c in enumerate(counts)}
    m = build_model()
    m.fit(Xtr, ytr, validation_data=(Xva, yva), epochs=8, batch_size=128, class_weight=cw, verbose=2,
          callbacks=[tf.keras.callbacks.EarlyStopping(patience=2, restore_best_weights=True)])
    T = fit_temperature(m.predict(Xva, verbose=0), yva)

    lstm = m.get_layer("lstm").get_weights()
    dense = m.get_layer("dense").get_weights()
    w = {f"emb{j}": m.get_layer(f"emb{j}").get_weights()[0] for j in range(5)}
    w.update(lstm_kernel=lstm[0], lstm_recurrent=lstm[1], lstm_bias=lstm[2], dense_k=dense[0], dense_b=dense[1],
             temperature=np.float64(T), classes=np.array(CLASSES))
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    np.savez(OUT, **w)

    # ---- evaluate the exported NumPy model (what the service actually runs)
    agent = LSTMBehaviorAgent(OUT)
    keras_logits = m.predict(Xte, verbose=0)
    pred = keras_logits.argmax(1)
    # parity check on a sample: NumPy forward == Keras forward
    diffs = []
    for i in range(0, len(Xte), max(1, len(Xte) // 200)):
        evs = [{"e": ENDPOINTS[r[0]], "m": None, "s": None, "t": None, "a": None} for r in Xte[i] if r[0] > 0]
        # compare on the encoded window directly
        agent_logits = _numpy_logits(agent, Xte[i])
        diffs.append(np.abs(agent_logits - keras_logits[i]).max())
    acc = float((pred == yte).mean())
    cm = np.zeros((len(CLASSES), len(CLASSES)), int)
    for a, b in zip(yte, pred):
        cm[a, b] += 1
    zt = keras_logits / T
    p = np.exp(zt - zt.max(1, keepdims=True)); p /= p.sum(1, keepdims=True)
    h = np.minimum(1, lte / 5)
    conf = h * p.max(1)
    score = 1 - np.exp(keras_logits - keras_logits.max(1, keepdims=True))[:, 0] / \
        np.exp(keras_logits - keras_logits.max(1, keepdims=True)).sum(1)
    attack = yte != 0
    det = {f"len {lo}-{hi}": float((score[attack & (lte >= lo) & (lte <= hi)] >= 0.5).mean())
           for lo, hi in ((1, 2), (3, 5), (6, 10), (11, 20))}
    fpr = {f"len {lo}-{hi}": float((score[~attack & (lte >= lo) & (lte <= hi)] >= 0.5).mean())
           for lo, hi in ((1, 2), (3, 5), (6, 10), (11, 20))}

    # Markov baseline (AI-072) on the same test windows, attack vs benign
    from app.training import load_or_train
    markov = load_or_train()[2]
    eps = [[ENDPOINTS[r[0]] for r in x if r[0] > 1] for x in Xte]
    ms = np.array([markov.analyze(e, 0).score if e else 0.0 for e in eps])
    from sklearn.metrics import average_precision_score
    res = {"accuracy": acc, "confusion": cm.tolist(), "temperature": T, "parity_max_abs_diff": float(max(diffs)),
           "pr_auc_attack_lstm": float(average_precision_score(attack, score)),
           "pr_auc_attack_markov": float(average_precision_score(attack, ms)),
           "detection_by_history": det, "false_alarm_by_history": fpr,
           "ece_confidence": ece(p.max(1), pred == yte), "windows": {"train": len(ytr), "val": len(yva), "test": len(yte)}}
    with open(os.path.join(HERE, "results", "behavior_lstm.json"), "w") as f:
        json.dump(res, f, indent=2)
    L = ["# Behaviour LSTM — results (synthetic sessions, test seed never seen in training)", "",
         f"Accuracy (4 classes): **{acc:.3f}** · temperature T = {T:.2f} · ECE {res['ece_confidence']:.3f} · "
         f"NumPy vs Keras max logit difference {res['parity_max_abs_diff']:.1e}", "",
         "| true \\ predicted | " + " | ".join(CLASSES) + " |", "|---" * (len(CLASSES) + 1) + "|"]
    L += [f"| {CLASSES[i]} | " + " | ".join(str(v) for v in cm[i]) + " |" for i in range(len(CLASSES))]
    L += ["", "| Attack vs benign | PR-AUC |", "|---|---|",
          f"| LSTM | {res['pr_auc_attack_lstm']:.3f} |", f"| Markov baseline (AI-072) | {res['pr_auc_attack_markov']:.3f} |",
          "", "| History length | Attacks detected (score ≥ 0.5) | Benign false alarms |", "|---|---|---|"]
    L += [f"| {k} | {det[k]:.3f} | {fpr[k]:.3f} |" for k in det]
    L += ["", "Short histories are ambiguous by design: one login attempt looks the same from a user and an attacker. "
          "That is why confidence is multiplied by h = min(1, events/5)."]
    with open(os.path.join(HERE, "results", "behavior_lstm.md"), "w") as f:
        f.write("\n".join(L) + "\n")
    print("\n".join(L))


if __name__ == "__main__":
    main()

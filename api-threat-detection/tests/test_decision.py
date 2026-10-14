"""Unit tests for the decision engine and config (SRS v1.1 NFR-029, AC-007 to AC-011, AC-017).

    python -m unittest discover -s tests -v        (from api-threat-detection/)
"""
import json
import os
import tempfile
import time
import unittest
from types import SimpleNamespace

from app.config import ConfigError, load_config
from app.decision import AGENT_NAMES, WeightManager, aggregate, explain, mcc, verdict_for


def R(score, conf, **detail):
    return SimpleNamespace(score=score, confidence=conf, detail=detail)


EQUAL = {n: 1.0 for n in AGENT_NAMES}


class TestAggregation(unittest.TestCase):
    def test_mode_a_formula(self):
        res = {"anomaly": R(0.2, 0.5), "payload": R(0.9, 1.0), "behavior": R(0.1, 0.25)}
        w = {"anomaly": 1.0, "payload": 2.0, "behavior": 0.5}
        a = aggregate(res, w, "A")
        num = 1.0 * 0.5 * 0.2 + 2.0 * 1.0 * 0.9 + 0.5 * 0.25 * 0.1
        den = 1.0 * 0.5 + 2.0 * 1.0 + 0.5 * 0.25
        self.assertAlmostEqual(a.score, num / den)
        self.assertAlmostEqual(a.numerator, num)
        self.assertAlmostEqual(a.denominator, den)
        self.assertAlmostEqual(sum(a.contributions.values()), num)

    def test_reproducible_from_stored_values(self):          # AI-042 / AC-007
        res = {"anomaly": R(0.33, 0.7), "payload": R(0.81, 0.92), "behavior": R(0.05, 0.4)}
        self.assertEqual(aggregate(res, EQUAL, "A").score, aggregate(res, EQUAL, "A").score)

    def test_modes_b_and_c(self):
        res = {"anomaly": R(0.2, 0.9), "payload": R(0.9, 0.9), "behavior": R(0.6, 0.9)}
        self.assertAlmostEqual(aggregate(res, EQUAL, "B").score, (0.2 + 0.9 + 0.6) / 3)
        self.assertAlmostEqual(aggregate(res, EQUAL, "C").score, 2 / 3)

    def test_range_always_0_1(self):                           # AI-039 / AC-008
        for s in (0.0, 1.0):
            for c in (0.0001, 1.0):
                res = {n: R(s, c) for n in AGENT_NAMES}
                for m in "ABC":
                    v = aggregate(res, EQUAL, m).score
                    self.assertTrue(0.0 <= v <= 1.0)

    def test_insufficient_evidence(self):                      # AI-040 / AC-009
        res = {n: R(0.9, 0.0) for n in AGENT_NAMES}
        self.assertIsNone(aggregate(res, EQUAL, "A").score)

    def test_no_agents(self):
        self.assertIsNone(aggregate({}, EQUAL, "A").score)

    def test_degraded_uses_survivors_only(self):
        res = {"payload": R(0.8, 1.0)}
        self.assertAlmostEqual(aggregate(res, EQUAL, "A").score, 0.8)


class TestBands(unittest.TestCase):                            # FR-042 / AC-008
    def test_edges(self):
        self.assertEqual(verdict_for(0.2999, 0.3, 0.7), "ALLOW")
        self.assertEqual(verdict_for(0.3, 0.3, 0.7), "FLAG")
        self.assertEqual(verdict_for(0.7, 0.3, 0.7), "FLAG")
        self.assertEqual(verdict_for(0.7001, 0.3, 0.7), "BLOCK")
        self.assertEqual(verdict_for(0.0, 0.3, 0.7), "ALLOW")
        self.assertEqual(verdict_for(1.0, 0.3, 0.7), "BLOCK")


class TestConfig(unittest.TestCase):                           # FR-043, FR-086 / AC-009
    def write(self, data):
        f = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump(data, f)
        f.close()
        self.addCleanup(os.unlink, f.name)
        return f.name

    def test_repo_config_is_valid(self):
        cfg = load_config()
        self.assertLess(cfg["thresholds"]["allow_below"], cfg["thresholds"]["block_above"])

    def test_threshold_order_rejected(self):
        with self.assertRaises(ConfigError) as e:
            load_config(self.write({"thresholds": {"allow_below": 0.7, "block_above": 0.3}}))
        self.assertIn("thresholds", str(e.exception))

    def test_bad_values_named(self):
        for bad, key in (({"aggregation": {"mode": "Z"}}, "aggregation.mode"),
                         ({"weights": {"min": 0}}, "weights.min"),
                         ({"agents": {"disabled": ["nope"]}}, "agents.disabled"),
                         ({"agents": {"failure_policy": "maybe"}}, "failure_policy")):
            with self.assertRaises(ConfigError) as e:
                load_config(self.write(bad))
            self.assertIn(key, str(e.exception))

    def test_broken_json(self):
        f = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        f.write("{not json")
        f.close()
        self.addCleanup(os.unlink, f.name)
        with self.assertRaises(ConfigError):
            load_config(f.name)


class TestWeights(unittest.TestCase):                          # AI-046 to AI-055 / AC-017
    CFG = {"initial": 1.0, "min": 0.1, "max": 2.0, "alpha": 0.3, "max_delta": 0.2,
           "update_every": 50, "window": 200, "min_positives": 10, "use_analyst_labels": True, "frozen": False}

    def feed(self, wm, n, attack_every=2):
        """payload agent always right, anomaly always wrong, behavior random-ish."""
        for i in range(n):
            y = int(i % attack_every == 0)
            wm.feedback({"payload": 0.9 if y else 0.1, "anomaly": 0.1 if y else 0.9,
                         "behavior": 0.9 if i % 3 == 0 else 0.1}, y)

    def test_mcc(self):
        self.assertAlmostEqual(mcc(10, 0, 0, 10), 1.0)
        self.assertAlmostEqual(mcc(0, 10, 10, 0), -1.0)
        self.assertEqual(mcc(0, 0, 0, 0), 0.0)

    def test_no_update_before_n(self):
        wm = WeightManager(self.CFG)
        self.feed(wm, 49)
        self.assertEqual(wm.updates, 0)
        self.assertEqual(wm.weights, {n: 1.0 for n in AGENT_NAMES})

    def test_good_agent_gains_bad_agent_loses_bounded(self):
        wm = WeightManager(self.CFG)
        self.feed(wm, 50)
        self.assertEqual(wm.updates, 1)
        self.assertGreater(wm.weights["payload"], 1.0)
        self.assertLess(wm.weights["anomaly"], 1.0)
        for n in AGENT_NAMES:
            self.assertLessEqual(abs(wm.weights[n] - 1.0), self.CFG["max_delta"] + 1e-9)

    def test_bounds_hold_over_many_updates(self):
        wm = WeightManager(self.CFG)
        self.feed(wm, 5000)
        for w in wm.weights.values():
            self.assertTrue(self.CFG["min"] <= w <= self.CFG["max"])
        self.assertLess(wm.weights["anomaly"], wm.weights["payload"])

    def test_skip_when_few_attacks(self):
        wm = WeightManager(self.CFG)
        for _ in range(50):
            wm.feedback({n: 0.1 for n in AGENT_NAMES}, 0)
        self.assertEqual(wm.updates, 0)
        self.assertEqual(wm.skipped, 1)
        self.assertTrue(wm.log[-1]["skipped"])

    def test_frozen(self):
        wm = WeightManager(dict(self.CFG, frozen=True))
        self.feed(wm, 200)
        self.assertEqual(wm.updates, 0)

    def test_analyst_labels_can_be_ignored(self):
        wm = WeightManager(dict(self.CFG, use_analyst_labels=False))
        self.assertIsNone(wm.feedback({n: 0.9 for n in AGENT_NAMES}, 1, "analyst"))
        self.assertEqual(wm.seen, 0)

    def test_audit_callback(self):
        entries = []
        wm = WeightManager(self.CFG, on_update=entries.append)
        self.feed(wm, 100)
        self.assertEqual(len(entries), 2)
        for k in ("old", "new", "window", "positives", "provenance", "ts"):
            self.assertIn(k, entries[0])


class TestExplain(unittest.TestCase):
    def test_contains_thresholds_and_degraded(self):
        res = {"payload": R(0.95, 1.0, reason="Payload looks like sqli", attack_type="sqli")}
        agg = aggregate(res, EQUAL, "A")
        ex = explain(res, EQUAL, agg.score, verdict_for(agg.score), [], agg=agg,
                     excluded={"anomaly": "timed out after 150 ms"})
        self.assertIn("Degraded", ex["summary"])
        self.assertEqual(ex["structured"]["thresholds"], {"allow_below": 0.3, "block_above": 0.7})
        self.assertEqual(ex["structured"]["lead_agent"], "payload")
        self.assertIn("anomaly", ex["structured"]["excluded"])

    def test_failure_policy_text(self):
        agg = aggregate({}, EQUAL, "A")
        ex = explain({}, EQUAL, None, "FLAG", [], agg=agg, policy_used="fail_open_flag")
        self.assertIn("failure policy", ex["summary"])


class TestPipeline(unittest.TestCase):
    """Timeouts, disabled agents and fail-open, with fake agents (no model files needed)."""

    def make(self, overrides=None, payload_delay=0.0, payload_raises=False):
        from app.pipeline import Pipeline

        class Fake:
            def __init__(self, s, c, delay=0.0, raises=False):
                self.s, self.c, self.delay, self.raises = s, c, delay, raises

            def analyze(self, *a):
                if self.delay:
                    time.sleep(self.delay)
                if self.raises:
                    raise RuntimeError("boom")
                return SimpleNamespace(score=self.s, confidence=self.c, detail={"reason": "x"})

        cfg = load_config(overrides=overrides or {})
        agents = (Fake(0.2, 0.8), Fake(0.9, 0.9, payload_delay, payload_raises), Fake(0.1, 0.5))
        p = Pipeline(agents, ":memory:", cfg=cfg)
        self.addCleanup(p.db.close)
        return p

    REQ = {"method": "GET", "path": "/search", "endpoint": "/search", "query": "q=x'", "body": "",
           "headers": {"User-Agent": "Mozilla/5.0"}, "ip": "1.2.3.4", "user": "u1", "ts": 0.0, "label": None}

    def test_timeout_excludes_agent(self):                      # FR-033, FR-034 / AC-010
        p = self.make({"agents": {"timeout_ms": 50}}, payload_delay=0.3)
        rec = p.process(dict(self.REQ), force_ai=True)
        self.assertIn("payload", rec["excluded"])
        self.assertTrue(rec["degraded"])
        self.assertNotIn("payload", rec["agents"])

    def test_error_excludes_agent(self):
        p = self.make(payload_raises=True)
        rec = p.process(dict(self.REQ), force_ai=True)
        self.assertIn("error", rec["excluded"]["payload"])

    def test_all_disabled_fail_open(self):                      # FR-036 / AC-011
        p = self.make({"agents": {"disabled": list(AGENT_NAMES)}})
        rec = p.process(dict(self.REQ), force_ai=True)
        self.assertEqual(rec["verdict"], "FLAG")
        self.assertEqual(rec["policy_used"], "fail_open_flag")
        self.assertIsNone(rec["score"])

    def test_fail_closed(self):
        p = self.make({"agents": {"disabled": list(AGENT_NAMES), "failure_policy": "fail_closed"}})
        self.assertEqual(p.process(dict(self.REQ), force_ai=True)["verdict"], "BLOCK")

    def test_mode_override_recorded(self):
        p = self.make()
        rec = p.process(dict(self.REQ), force_ai=True, mode="C")
        self.assertEqual(rec["mode"], "C")
        self.assertAlmostEqual(rec["score"], 1 / 3, places=3)


if __name__ == "__main__":
    unittest.main()

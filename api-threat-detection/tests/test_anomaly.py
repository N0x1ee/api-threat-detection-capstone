"""Anomaly agent tests (SRS v1.1 AI-015 to AI-018, AI-032, AI-033, AI-036, AI-070, Table 5.2)."""
import random
import unittest

import numpy as np

from app.agents import FEATURES, AnomalyAgent, extract_features
from app.traffic import generate_session

REQ = {"method": "POST", "path": "/api/orders/12/items", "endpoint": "/api/orders/{id}/items",
       "query": "page=2&sort=asc", "body": '{"qty": 3}',
       "headers": {"User-Agent": "Mozilla/5.0", "Content-Type": "application/json", "Content-Length": "10"}}


def normal(n_sessions, seed):
    rng = random.Random(seed)
    return [r for _ in range(n_sessions) for r in generate_session(rng, "normal", 0)]


class FeatureTest(unittest.TestCase):
    def test_seventeen_features_in_table_order(self):
        self.assertEqual(len(FEATURES), 17)
        self.assertEqual(len(extract_features(REQ)), 17)

    def test_values(self):
        f = dict(zip(FEATURES, extract_features(REQ)))
        self.assertEqual(f["query_length"], len("page=2&sort=asc"))
        self.assertEqual(f["query_param_count"], 2)
        self.assertEqual(f["path_depth"], 4)
        self.assertEqual(f["header_count"], 3)
        self.assertEqual(f["method_code"], 2)                 # POST
        self.assertEqual(f["content_type_code"], 1)           # json
        self.assertEqual(f["length_mismatch"], 0.0)
        self.assertEqual(f["non_printable_count"], 0)

    def test_length_mismatch_and_nonprintable(self):
        r = dict(REQ, body="abc\x00\x01", headers={"Content-Length": "999"})
        f = dict(zip(FEATURES, extract_features(r)))
        self.assertEqual(f["length_mismatch"], 1.0)
        self.assertEqual(f["non_printable_count"], 2)
        self.assertEqual(f["content_type_code"], 0)           # no content type

    def test_empty_request_does_not_crash(self):
        self.assertEqual(len(extract_features({})), 17)


class AnomalyAgentTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.agent = AnomalyAgent(n_estimators=50).fit(normal(150, 1), validation=normal(40, 2))
        cls.val = normal(30, 3)

    def test_per_tree_scores_reproduce_sklearn(self):
        X = np.array([extract_features(r) for r in self.val[:100]])
        mine = 2.0 ** np.log2(self.agent.tree_scores(X)).mean(1)
        np.testing.assert_allclose(mine, -self.agent.model.score_samples(X), atol=1e-9)

    def test_score_and_confidence_in_range(self):         # AI-016, AI-032
        for r in self.val[:200] + [REQ]:
            res = self.agent.analyze(r)
            self.assertTrue(0.0 <= res.score <= 1.0)
            self.assertTrue(0.0 <= res.confidence <= 1.0)

    def test_deterministic(self):                         # AI-032
        a, b = self.agent.analyze(REQ), self.agent.analyze(REQ)
        self.assertEqual((a.score, a.confidence), (b.score, b.confidence))

    def test_confidence_from_tree_spread(self):           # ADD-25
        res = self.agent.analyze(self.val[0])
        d = res.detail
        self.assertAlmostEqual(res.confidence, 1 - min(1, d["tree_spread"] / d["sigma_ref"]))

    def test_confident_benign_possible(self):             # AI-033
        res = [self.agent.analyze(r) for r in self.val]
        self.assertTrue(any(x.score < 0.3 and x.confidence > 0.2 for x in res))

    def test_failure_returns_minimum_confidence(self):    # AI-036
        broken = AnomalyAgent(n_estimators=10).fit(normal(30, 4))
        broken.sigma_ref = None                               # forces the confidence step to fail
        self.assertEqual(broken.analyze(REQ).confidence, 0.0)

    def test_top_features_ranked_by_z(self):              # AI-017
        top = self.agent.analyze(dict(REQ, query="x" * 4000)).detail["top_features"]
        self.assertEqual(len(top), 5)
        zs = [abs(t["z"]) for t in top]
        self.assertEqual(zs, sorted(zs, reverse=True))
        self.assertIn(top[0]["feature"], FEATURES)


if __name__ == "__main__":
    unittest.main()

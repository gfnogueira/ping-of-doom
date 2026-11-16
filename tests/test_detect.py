import unittest

from pod.detect import analyze
from tests.helpers import ping_like, tunnel_like


def verdict(frames, **kw):
    _, findings = analyze(frames, **kw)
    return findings[0]["verdict"], findings[0]["rules"]


class DetectTests(unittest.TestCase):
    def test_normal_ping_is_clean(self):
        self.assertEqual(verdict(ping_like(60, 56, 1.0)), ("ok", []))

    def test_windows_style_ping_is_clean(self):
        self.assertEqual(verdict(ping_like(60, 32, 1.0)), ("ok", []))

    def test_large_but_honest_ping_is_only_a_notice(self):
        state, rules = verdict(ping_like(30, 1400, 1.0))
        self.assertEqual(state, "notice")
        self.assertEqual(rules, ["big_payload"])

    def test_mid_size_honest_ping_is_only_a_notice(self):
        # 200 distinct incrementing bytes give about 7.6 bits of entropy
        state, rules = verdict(ping_like(30, 200, 1.0))
        self.assertEqual((state, rules), ("notice", ["big_payload"]))

    def test_few_big_pings_do_not_fire(self):
        self.assertEqual(verdict(ping_like(3, 1400, 1.0)), ("ok", []))

    def test_fast_honest_ping_flood_is_a_notice(self):
        state, rules = verdict(ping_like(300, 56, 0.001))
        self.assertEqual((state, rules), ("notice", ["high_rate"]))

    def test_tunnel_like_traffic_is_suspicious(self):
        state, rules = verdict(tunnel_like(200, 0.002))
        self.assertEqual(state, "suspicious")
        for rule in ("big_payload", "high_entropy", "reply_mismatch"):
            self.assertIn(rule, rules)

    def test_slow_tunnel_still_caught_by_mismatch(self):
        state, rules = verdict(tunnel_like(40, 2.0))
        self.assertEqual(state, "suspicious")
        self.assertNotIn("high_rate", rules)
        self.assertIn("reply_mismatch", rules)


if __name__ == "__main__":
    unittest.main()

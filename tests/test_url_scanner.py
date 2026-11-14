import unittest
from url_scanner import analyze_url

class URLScannerTests(unittest.TestCase):
    def test_empty_url_is_invalid(self):
        result = analyze_url("")
        self.assertEqual(result["risk_level"], "Unknown")
        self.assertTrue(result["review_required"])

    def test_plain_https_domain_has_no_rule_warnings(self):
        result = analyze_url("https://example.com")
        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["risk_level"], "Low")
        self.assertFalse(result["review_required"])

    def test_http_and_ip_raise_caution(self):
        result = analyze_url("http://192.0.2.10/login")
        self.assertGreaterEqual(result["risk_score"], 30)
        self.assertTrue(result["review_required"])

    def test_gambling_wording_is_flagged_as_category(self):
        result = analyze_url("https://example.com/aviator-betting")
        self.assertTrue(any("gambling or betting-related" in x for x in result["reasons"]))
        self.assertTrue(any("not evidence" in x for x in result["informational"]))

    def test_tracking_parameters_are_context_not_fraud_proof(self):
        result = analyze_url("https://example.com/?click_id=123")
        self.assertTrue(any("tracking parameters" in x for x in result["informational"]))

    def test_unsupported_scheme_is_rejected(self):
        result = analyze_url("javascript:alert(1)")
        self.assertEqual(result["risk_level"], "Unknown")

if __name__ == "__main__":
    unittest.main()

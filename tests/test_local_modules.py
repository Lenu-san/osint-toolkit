"""Tests unitaires d'osint-toolkit sur les fonctions qui n'ont pas besoin
du réseau : analyse d'en-têtes d'e-mail et notation des en-têtes de sécurité
(l'appel HTTP est remplacé par une réponse simulée).

    python -m unittest discover -s tests -v
"""

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from osintkit import email_headers, security_headers  # noqa: E402

SAMPLE = os.path.join(os.path.dirname(__file__), "..", "samples", "exemple-phishing.eml")


class EmailHeadersTests(unittest.TestCase):
    def test_sample_phishing_raises_expected_alerts(self):
        with open(SAMPLE, encoding="utf-8") as handle:
            result = email_headers.analyze(handle.read())
        self.assertEqual(result["auth"], {"SPF": "fail", "DKIM": "none", "DMARC": "fail"})
        levels = [f["level"] for f in result["findings"]]
        self.assertEqual(levels.count("ALERTE"), 4)
        self.assertEqual(levels.count("ATTENTION"), 1)
        self.assertEqual(result["infos"]["Sauts (Received)"], "1")

    def test_legitimate_message_has_no_alert(self):
        raw = (
            "Return-Path: <noreply@example.org>\n"
            "Authentication-Results: mx.example.net; spf=pass; dkim=pass; dmarc=pass\n"
            "From: Service <noreply@example.org>\n"
            "To: user@example.net\n"
            "Subject: Bonjour\n\n"
            "corps\n"
        )
        result = email_headers.analyze(raw)
        self.assertEqual(result["findings"], [])

    def test_missing_authentication_results_is_reported_as_info(self):
        raw = "From: a@example.org\nTo: b@example.net\nSubject: x\n\ncorps\n"
        result = email_headers.analyze(raw)
        self.assertEqual([f["level"] for f in result["findings"]], ["INFO"])


class SecurityHeadersTests(unittest.TestCase):
    def _grade(self, headers):
        with mock.patch.object(security_headers, "get_full", return_value=(200, headers, b"")):
            return security_headers.analyze("example.org")

    def test_all_headers_present_is_grade_a(self):
        headers = {name: "on" for name, _, _ in security_headers.CHECKS}
        result = self._grade(headers)
        self.assertEqual(result["grade"], "A")
        self.assertEqual(result["score"], result["max"])
        self.assertEqual(result["url"], "https://example.org")

    def test_no_header_is_grade_f(self):
        result = self._grade({})
        self.assertEqual(result["grade"], "F")
        self.assertTrue(all(not r["present"] for r in result["results"]))

    def test_partial_headers_middle_grade(self):
        result = self._grade({"Strict-Transport-Security": "max-age=1", "X-Frame-Options": "DENY"})
        self.assertEqual(result["score"], 3)
        self.assertIn(result["grade"], ("C", "D"))


if __name__ == "__main__":
    unittest.main()

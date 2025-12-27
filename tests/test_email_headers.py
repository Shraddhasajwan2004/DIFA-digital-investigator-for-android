import unittest
from backend.analysis.email_header_analyzer import extract_spf_dkim_dmarc

class TestEmailHeaderAnalyzer(unittest.TestCase):

    def test_valid_headers(self):
        header = "Received-SPF: pass (google.com: domain of example@gmail.com) smtp.mailfrom=example@gmail.com; dkim=pass; dmarc=pass"
        spf, dkim, dmarc = extract_spf_dkim_dmarc(header)
        self.assertEqual(spf.lower(), "pass")
        self.assertEqual(dkim.lower(), "pass")
        self.assertEqual(dmarc.lower(), "pass")

    def test_missing_headers(self):
        header = "Received: from mail.example.com"
        spf, dkim, dmarc = extract_spf_dkim_dmarc(header)
        self.assertEqual(spf, "N/A")
        self.assertEqual(dkim, "N/A")
        self.assertEqual(dmarc, "N/A")

    def test_malformed_header(self):
        header = "spf=fail dkim=neutral dmarc=none"
        spf, dkim, dmarc = extract_spf_dkim_dmarc(header)
        self.assertEqual(spf.lower(), "fail")
        self.assertEqual(dkim.lower(), "neutral")
        self.assertEqual(dmarc.lower(), "none")

if __name__ == '__main__':
    unittest.main()

import os
import unittest
from backend.analysis.dns_log_parser import parse_dns_log_line, classify_risk
from backend.analysis.dns_log_parser import analyze_dns_logs
from backend.analysis.dns_log_parser import parse_dns_log_line, classify_risk
class TestDNSLogAnalyzer(unittest.TestCase):

    def test_parse_valid_log_line(self):
        line = "2024-07-08 22:45:13 query suspiciousdomain.onion"
        timestamp, domain = parse_dns_log_line(line)
        self.assertEqual(str(timestamp), "2024-07-08 22:45:13")
        self.assertEqual(domain, "suspiciousdomain.onion")

    def test_parse_invalid_log_line(self):
        line = "No timestamp here just garbage text"
        timestamp, domain = parse_dns_log_line(line)
        self.assertIsNone(timestamp)
        self.assertIsNone(domain)

    def test_high_risk_tld(self):
        domain = "darkwebsite.onion"
        risk = classify_risk(domain)
        self.assertEqual(risk, "High")

    def test_intermediate_risk_free_domain(self):
        domain = "user.duckdns.org"
        risk = classify_risk(domain)
        self.assertEqual(risk, "Intermediate")

    def test_low_risk_domain(self):
        domain = "example.com"
        risk = classify_risk(domain)
        self.assertEqual(risk, "Low")
def test_dns_analysis_sample():
    sample_log = """2024-06-12 08:45:00 query malware.bad-domain.biz
2024-06-12 18:00:00 query duckdns.org
2024-06-12 10:15:00 query secure.example.com"""
    os.makedirs("test_logs", exist_ok=True)
    sample_path = "test_logs/sample_dns.txt"
    with open(sample_path, "w") as f:
        f.write(sample_log)

    df, csv_path, hash_path, zip_path =      analyze_dns_logs(sample_path)

    assert not df.empty, "Parsed DataFrame is empty."
    assert "Domain" in df.columns
    assert any(df["Heuristic Risk"] == "High"), "Expected high risk not found."
    assert os.path.exists(csv_path), "CSV report not generated."
    assert os.path.exists(hash_path), "Hash file missing."
    assert os.path.exists(zip_path), "ZIP archive missing."
class TestDNSLogAnalyzer(unittest.TestCase):

    def test_parse_valid_line(self):
        line = "2025-07-08 10:34:12 query example.com"
        timestamp, domain = parse_dns_log_line(line)
        self.assertEqual(domain, "example.com")
        self.assertEqual(timestamp.strftime("%H:%M:%S"), "10:34:12")

    def test_parse_invalid_line(self):
        line = "Random unrelated text"
        timestamp, domain = parse_dns_log_line(line)
        self.assertIsNone(timestamp)
        self.assertIsNone(domain)

    def test_risk_classification(self):
        domain1 = "leak-onion.xyz"
        domain2 = "duckdns.org"
        domain3 = "safe.example.com"

        risk1, _ = classify_risk(domain1)
        risk2, _ = classify_risk(domain2)
        risk3, _ = classify_risk(domain3)

        self.assertEqual(risk1, "High")
        self.assertEqual(risk2, "Intermediate")
        self.assertEqual(risk3, "Low")
import pytest
from backend.analysis import dns_log_analyzer

def test_parse_line_valid():
    line = "2025-07-08 13:42:01 query example.xyz"
    ts, domain = dns_log_analyzer.parse_dns_log_line(line)
    assert ts is not None
    assert domain == "example.xyz"

def test_classify_risk_high():
    domain = "malicious.c2.onion"
    risk, reason = dns_log_analyzer.classify_risk(domain)
    assert risk == "High"

def test_model_prediction():
    if dns_log_analyzer.model:
        ts = dns_log_analyzer.datetime.now()
        risk = dns_log_analyzer.predict_model_risk("test.example.com", ts)
        assert risk in ["Low", "Intermediate", "High", "Unknown"]
    


if __name__ == "__main__":
    unittest.main()

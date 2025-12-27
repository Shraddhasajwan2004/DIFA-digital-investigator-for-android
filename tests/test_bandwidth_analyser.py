import unittest
from backend.analysis.bandwidth_analyser import extract_bandwidth_info

class TestBandwidthAnalyzer(unittest.TestCase):
    def test_valid_pcap(self):
        test_file = "tests/sample_valid.pcap"
        df = extract_bandwidth_info(test_file)
        self.assertIsInstance(df, object)
        self.assertIn("Risk Level", df.columns)

    def test_empty_pcap(self):
        df = extract_bandwidth_info("tests/empty.pcap")
        self.assertTrue(df.empty)

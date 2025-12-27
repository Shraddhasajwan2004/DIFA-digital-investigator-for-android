# tests/test_hidden_apps.py

import unittest
import os
from backend.analysis.hidden_apps import analyze_installed_apps

class TestHiddenAppsAnalyzer(unittest.TestCase):

    def setUp(self):
        self.sample_file = "tests/sample_data/installed_apps_sample.json"
        os.makedirs("tests/sample_data", exist_ok=True)
        with open(self.sample_file, "w") as f:
            f.write("""
[
    {
        "package_name": "com.example.visibleapp",
        "has_launcher_intent": true,
        "permissions": ["android.permission.INTERNET"],
        "app_size_mb": 20,
        "last_used_days_ago": 3
    },
    {
        "package_name": "com.spyware.stealth",
        "has_launcher_intent": false,
        "permissions": ["android.permission.READ_SMS", "android.permission.CAMERA"],
        "app_size_mb": 5,
        "last_used_days_ago": 200
    }
]
            """)

    def test_analyze_apps_output(self):
        df, csv_path, hash_path, zip_path = analyze_installed_apps(self.sample_file)
        self.assertIsNotNone(df)
        self.assertEqual(len(df), 2)
        self.assertIn("Risk Level", df.columns)

        high_risk_apps = df[df["Risk Level"] == "High"]
        self.assertEqual(len(high_risk_apps), 1)
        self.assertIn("com.spyware.stealth", high_risk_apps["Package Name"].values)

    def tearDown(self):
        os.remove(self.sample_file)

if __name__ == "__main__":
    unittest.main()

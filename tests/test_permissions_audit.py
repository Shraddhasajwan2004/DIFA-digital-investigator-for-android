# tests/test_permissions_audit.py

import pytest
from backend.analysis.permissions_audit import analyze_permissions

def test_permission_risk():
    sample=[{"app_name":"A","package":"a","permissions":["CAMERA","INTERNET"]},
            {"app_name":"B","package":"b","permissions":["READ_CONTACTS"]}]
    df = analyze_permissions(sample)
    assert df.loc[0,"Risk Level"]=="High"
    assert df.loc[1,"Risk Level"]=="Low"

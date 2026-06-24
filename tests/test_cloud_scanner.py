"""Tests for cloud scanner."""
from __future__ import annotations

from scanners import CloudScanner, CloudScanResult


def test_cloud_scanner_initializes():
    scanner = CloudScanner()
    assert scanner.profile == "default"
    assert scanner.region == "us-east-1"


def test_cloud_scan_result_serializes():
    result = CloudScanResult(profile="test", region="us-east-1")
    data = result.to_dict()
    assert data["profile"] == "test"
    assert data["region"] == "us-east-1"
    assert "findings" in data

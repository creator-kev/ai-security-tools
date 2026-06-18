"""Tests for AD CS Scanner"""

import pytest
from unittest.mock import Mock, MagicMock, patch
from dataclasses import dataclass

# Import the scanner
import sys
sys.path.insert(0, "src")

from scanners.adcs_scanner import (
    ADCSScanner,
    ADCSVuln,
    ESCType,
    ADCSScanResult,
)


class TestESCType:
    """Test ESCType enum."""

    def test_esc_types_exist(self):
        assert ESCType.ESC1 == "ESC1"
        assert ESCType.ESC2 == "ESC2"
        assert ESCType.ESC3 == "ESC3"
        assert ESCType.ESC4 == "ESC4"
        assert ESCType.ESC5 == "ESC5"
        assert ESCType.ESC6 == "ESC6"
        assert ESCType.ESC7 == "ESC7"
        assert ESCType.ESC8 == "ESC8"
        assert ESCType.ESC9 == "ESC9"
        assert ESCType.ESC10 == "ESC10"
        assert ESCType.ESC11 == "ESC11"


class TestADCSVuln:
    """Test ADCSVuln dataclass."""

    def test_vuln_creation(self):
        vuln = ADCSVuln(
            template_name="TestTemplate",
            esc_type=ESCType.ESC1,
            vulnerable_perms=["Enroll", "Client Authentication"],
            exploit_command="certipy req ...",
            severity="CRITICAL",
            cvss=9.8,
        )
        assert vuln.template_name == "TestTemplate"
        assert vuln.esc_type == ESCType.ESC1
        assert vuln.severity == "CRITICAL"
        assert vuln.cvss == 9.8

    def test_vuln_to_dict(self):
        vuln = ADCSVuln(
            template_name="TestTemplate",
            esc_type=ESCType.ESC1,
            vulnerable_perms=["Enroll"],
            exploit_command="certipy req ...",
        )
        d = vuln.to_dict()
        assert d["template_name"] == "TestTemplate"
        assert d["esc_type"] == "ESC1"
        assert d["vulnerable_perms"] == ["Enroll"]


class TestADCSScanner:
    """Test ADCSScanner."""

    def test_scanner_init(self):
        scanner = ADCSScanner()
        assert scanner.config == {}
        assert scanner.ldap_timeout == 30
        assert scanner.page_size == 1000

    def test_scanner_init_with_config(self, tmp_path):
        config_file = tmp_path / "test_config.yaml"
        config_file.write_text("""
scanners:
  adcs:
    ldap_timeout: 60
    page_size: 500
""")
        scanner = ADCSScanner(str(config_file))
        assert scanner.ldap_timeout == 60
        assert scanner.page_size == 500

    @patch("scanners.adcs_scanner.LDAP3_AVAILABLE", False)
    def test_connect_no_ldap3(self):
        scanner = ADCSScanner()
        result = scanner._connect("10.0.0.1", "user", "pass", "domain.local")
        assert result is False
        assert "ldap3 not installed" in scanner._errors[0]

    def test_analyze_template_esc1(self):
        scanner = ADCSScanner()
        # Template with ESC1 conditions:
        # - Enrollee supplies subject (cert_name_flag & 0x1)
        # - Has Client Auth EKU
        # - No manager approval required
        template = {
            "cn": "ESC1Template",
            "mspki-certificate-name-flag": "1",  # 0x1 = ENROLLEE_SUPPLIES_SUBJECT
            "mspki-enrollment-flag": "0",  # No approval required
            "pkiextendedkeyusage": ["1.3.6.1.5.5.7.3.2"],  # Client Auth
        }
        vulns = scanner._analyze_template(template)
        esc1_vulns = [v for v in vulns if v.esc_type == ESCType.ESC1]
        assert len(esc1_vulns) == 1
        assert esc1_vulns[0].template_name == "ESC1Template"
        assert esc1_vulns[0].severity == "CRITICAL"
        assert esc1_vulns[0].cvss == 9.8

    def test_analyze_template_esc2(self):
        scanner = ADCSScanner()
        # Template with Any Purpose EKU
        template = {
            "cn": "ESC2Template",
            "mspki-enrollment-flag": "0",
            "pkiextendedkeyusage": ["2.5.29.37.0"],  # Any Purpose
        }
        vulns = scanner._analyze_template(template)
        esc2_vulns = [v for v in vulns if v.esc_type == ESCType.ESC2]
        assert len(esc2_vulns) == 1
        assert esc2_vulns[0].severity == "CRITICAL"

    def test_analyze_template_esc3(self):
        scanner = ADCSScanner()
        # Template with Enrollment Agent EKU
        template = {
            "cn": "ESC3Template",
            "pkiextendedkeyusage": ["1.3.6.1.4.1.311.20.2.1"],  # Enrollment Agent
        }
        vulns = scanner._analyze_template(template)
        esc3_vulns = [v for v in vulns if v.esc_type == ESCType.ESC3]
        assert len(esc3_vulns) == 1
        assert esc3_vulns[0].severity == "HIGH"

    def test_analyze_template_esc9(self):
        scanner = ADCSScanner()
        # Schema version 1 (no security extension) + Client Auth
        template = {
            "cn": "ESC9Template",
            "mspki-template-schema-version": "1",
            "mspki-enrollment-flag": "0",
            "pkiextendedkeyusage": ["1.3.6.1.5.5.7.3.2"],  # Client Auth
        }
        vulns = scanner._analyze_template(template)
        esc9_vulns = [v for v in vulns if v.esc_type == ESCType.ESC9]
        assert len(esc9_vulns) == 1
        assert esc9_vulns[0].severity == "HIGH"

    def test_analyze_template_no_vuln(self):
        scanner = ADCSScanner()
        # Secure template: requires approval, no dangerous EKUs
        template = {
            "cn": "SecureTemplate",
            "mspki-certificate-name-flag": "0",
            "mspki-enrollment-flag": "2",  # Requires approval
            "pkiextendedkeyusage": ["1.3.6.1.5.5.7.3.1"],  # Server Auth only
        }
        vulns = scanner._analyze_template(template)
        assert len(vulns) == 0

    def test_gen_esc1_command(self):
        scanner = ADCSScanner()
        cmd = scanner._gen_esc1_command("TestTemplate")
        assert "certipy req" in cmd
        assert "TestTemplate" in cmd
        assert "administrator" in cmd
        assert "certipy auth" in cmd

    def test_gen_esc8_command(self):
        scanner = ADCSScanner()
        cmd = scanner._gen_esc8_command("10.0.0.1", "domain.local")
        assert "ntlmrelayx" in cmd
        assert "petitpotam" in cmd

    def test_scan_result_to_dict(self):
        result = ADCSScanResult(
            domain="test.local",
            dc_ip="10.0.0.1",
            username="user",
            total_templates_scanned=5,
        )
        d = result.to_dict()
        assert d["domain"] == "test.local"
        assert d["dc_ip"] == "10.0.0.1"
        assert d["username"] == "user"
        assert d["total_templates_scanned"] == 5


class TestIntegration:
    """Integration-style tests (mocked LDAP)."""

    @patch("scanners.adcs_scanner.LDAP3_AVAILABLE", True)
    @patch("scanners.adcs_scanner.Server")
    @patch("scanners.adcs_scanner.Connection")
    def test_full_scan_flow(self, mock_conn_class, mock_server_class):
        # Setup mocks
        mock_server = Mock()
        mock_server_class.return_value = mock_server

        mock_conn = Mock()
        mock_conn_class.return_value = mock_conn
        mock_conn.entries = []

        scanner = ADCSScanner()
        
        # This will fail due to no templates found, but tests the flow
        result = scanner.scan("10.0.0.1", "user", "pass", "domain.local")
        
        assert result.domain == "domain.local"
        assert result.dc_ip == "10.0.0.1"
        assert result.username == "user"
        mock_server_class.assert_called_once()
        mock_conn_class.assert_called_once()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
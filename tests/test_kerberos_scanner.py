"""Tests for KerberosScanner — mocked, no live AD required."""

from __future__ import annotations

import json
import logging
import types
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.kerberos_scanner import (
    DelegationFinding,
    DelegationType,
    HashcatMode,
    KerberoastHash,
    KerberosScanResult,
    KerberosScanner,
    ScanMode,
)


@pytest.fixture()
def scanner(tmp_path: Path) -> KerberosScanner:
    """Return a scanner pointing output at tmp_path."""
    out = tmp_path / "out"
    out.mkdir()
    return KerberosScanner(
        config_path=None,
        output_dir=str(out),
    )


# ---------------------------------------------------------------------------
# Data model tests
# ---------------------------------------------------------------------------

class TestDataModels:
    def test_kerberoast_hash_to_dict(self) -> None:
        h = KerberoastHash(
            username="svc-sql",
            spn="MSSQLSvc/sql01.corp.local:1433",
            hash="$krb5tgs$23$...",
            encryption="RC4-HMAC",
            hashcat_mode=HashcatMode.KERBEROS_RC4,
            hostname="sql01.corp.local",
            timestamp="2026-06-19T12:00:00Z",
        )
        d = h.to_dict()
        assert d["username"] == "svc-sql"
        assert d["hashcat_mode"] == "13100"
        assert d["encryption"] == "RC4-HMAC"

    def test_delegation_finding_to_dict(self) -> None:
        f = DelegationFinding(
            computer_name="WIN-01",
            delegation_type=DelegationType.UNCONSTRAINED,
            allowed_to_delegate_to=["cifs/win-01.corp.local"],
            user_account_control=524288,
        )
        d = f.to_dict()
        assert d["delegation_type"] == "unconstrained"
        assert d["user_account_control"] == 524288

    def test_scan_result_to_dict(self, scanner: KerberosScanner) -> None:
        r = KerberosScanResult(
            domain="corp.local",
            dc_ip="10.0.0.1",
            mode="all",
            asrep_hashes=[
                KerberoastHash(
                    username="svc-app",
                    hash="$krb5asrep$...",
                    encryption="RC4-HMAC",
                    hashcat_mode=HashcatMode.ASREP,
                    timestamp="2026-06-19T12:00:00Z",
                )
            ],
            kerberoast_hashes=[],
            delegation_findings=[],
            scan_errors=[],
        )
        d = r.to_dict()
        assert d["domain"] == "corp.local"
        assert len(d["asrep_hashes"]) == 1
        assert d["asrep_hashes"][0]["username"] == "svc-app"


# ---------------------------------------------------------------------------
# Config loading tests
# ---------------------------------------------------------------------------

class TestConfigLoading:
    def test_env_config(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setenv("KERB_DOMAIN", "lab.local")
        monkeypatch.setenv("KERB_DC_IP", "10.10.10.10")
        monkeypatch.setenv("KERB_OUTPUT_DIR", str(tmp_path / "out"))
        scanner = KerberosScanner(config_path=None, output_dir=str(tmp_path / "out"))
        assert scanner.domain == "lab.local"
        assert scanner.dc_ip == "10.10.10.10"


# ---------------------------------------------------------------------------
# ASREPRoast tests
# ---------------------------------------------------------------------------

class TestAsreproast:
    @patch("src.kerberos_scanner.subprocess.run")
    def test_scan_asreproast_success(
        self, mock_run: MagicMock, scanner: KerberosScanner, tmp_path: Path
    ) -> None:
        impacket_output = (
            "$krb5asrep$23$user@LAB.LOCAL:hashpart\n"
            "$krb5asrep$23$admin@LAB.LOCAL:hashpart2\n"
        )
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=impacket_output.encode(),
            stderr=b"",
        )

        result = scanner.scan_asreproast()

        assert len(result.asrep_hashes) == 2
        assert result.asrep_hashes[0].username == "user"
        assert result.asrep_hashes[0].hashcat_mode == "18200"

    @patch("src.kerberos_scanner.subprocess.run")
    def test_scan_asreproast_no_results(
        self, mock_run: MagicMock, scanner: KerberosScanner
    ) -> None:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=b"",
            stderr=b"",
        )
        result = scanner.scan_asreproast()
        assert result.asrep_hashes == []
        assert result.scan_errors == []

    @patch("src.kerberos_scanner.subprocess.run")
    def test_scan_asreproast_tool_missing(
        self, mock_run: MagicMock, scanner: KerberosScanner
    ) -> None:
        mock_run.side_effect = FileNotFoundError("impacket-GetNPUsers.py")
        result = scanner.scan_asreproast()
        assert len(result.scan_errors) > 0
        assert "impacket" in result.scan_errors[0].lower() or "GetNPUsers" in result.scan_errors[0]


# ---------------------------------------------------------------------------
# Kerberoast tests
# ---------------------------------------------------------------------------

class TestKerberoast:
    @patch("src.kerberos_scanner.subprocess.run")
    def test_scan_kerberoast_success(
        self, mock_run: MagicMock, scanner: KerberosScanner
    ) -> None:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=(
                "$krb5tgs$23$*svc-sql$MSSQLSvc/sql01.corp.local*$hash...\n"
                "$krb5tgs$23$*svc-app$HTTP/web01.corp.local*$hash2...\n"
            ).encode(),
            stderr=b"",
        )

        result = scanner.scan_kerberoast()

        assert len(result.kerberoast_hashes) == 2
        assert result.kerberoast_hashes[0].username == "svc-sql"
        assert result.kerberoast_hashes[0].spn.startswith("MSSQLSvc")

    @patch("src.kerberos_scanner.subprocess.run")
    def test_hashcat_mode_mapping(
        self, mock_run: MagicMock, scanner: KerberosScanner
    ) -> None:
        # AES256 ticket (type 18 in kerberos ticket)
        sample = "$krb5tgs$18$*user$HTTP/web*$aes256hash..."
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=sample.encode(),
            stderr=b"",
        )
        result = scanner.scan_kerberoast()
        assert result.kerberoast_hashes[0].hashcat_mode == "19800"

    @patch("src.kerberos_scanner.subprocess.run")
    def test_scan_kerberoast_empty(
        self, mock_run: MagicMock, scanner: KerberosScanner
    ) -> None:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=b"",
            stderr=b"",
        )
        result = scanner.scan_kerberoast()
        assert result.kerberoast_hashes == []


# ---------------------------------------------------------------------------
# Delegation audit tests
# ---------------------------------------------------------------------------

class TestDelegation:
    @patch("src.kerberos_scanner.ldap3")
    def test_scan_delegation_success(
        self, mock_ldap: MagicMock, scanner: KerberosScanner
    ) -> None:
        # Build a fake LDAP response
        mock_conn = MagicMock()
        mock_conn.search.return_value = True
        mock_conn.entries = [
            MagicMock(
                name="WIN-01$",
                user_account_control=524288,
                msds_allowedtodelegateto=["cifs/win-01.corp.local"],
            ),
            MagicMock(
                name="WIN-02$",
                user_account_control=0,
                msds_allowedtodelegateto=[],
            ),
        ]
        for entry in mock_conn.entries:
            entry.__getitem__ = lambda self, attr: (
                entry.msds_allowedtodelegateto
                if attr == "msDS-AllowedToDelegateTo"
                else entry.user_account_control
            )
        mock_ldap.Connection.return_value = mock_conn
        mock_ldap.SERVER.return_value = MagicMock()

        with patch.object(scanner, "_ldap_connect", return_value=mock_conn):
            result = scanner.scan_delegation()

        assert len(result.delegation_findings) >= 1
        types_found = {d.delegation_type for d in result.delegation_findings}
        assert DelegationType.UNCONSTRAINED in types_found

    def test_scan_delegation_no_ldap3(
        self, scanner: KerberosScanner, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Remove ldap3 from sys.modules
        import sys

        monkeypatch.setitem(sys.modules, "ldap3", None)
        result = scanner.scan_delegation()
        assert len(result.scan_errors) > 0


# ---------------------------------------------------------------------------
# Output tests
# ---------------------------------------------------------------------------

class TestOutput:
    def test_to_json(self, scanner: KerberosScanner, tmp_path: Path) -> None:
        result = KerberosScanResult(
            domain="lab.local",
            dc_ip="10.10.10.10",
            mode="all",
        )
        out_file = tmp_path / "result.json"
        scanner.to_json(result, str(out_file))
        assert out_file.exists()
        data = json.loads(out_file.read_text())
        assert data["domain"] == "lab.local"
        assert data["kerberoast_hashes"] == []

    def test_to_table_empty(self, scanner: KerberosScanner, caplog: pytest.LogCaptureFixture) -> None:
        result = KerberosScanResult(
            domain="lab.local", dc_ip="10.10.10.10", mode="all"
        )
        table = scanner.to_table(result)
        assert table is not None
        assert "lab.local" in table

    def test_to_json_includes_hashes(
        self, scanner: KerberosScanner, tmp_path: Path
    ) -> None:
        h = KerberoastHash(
            username="svc-http",
            spn="HTTP/web.corp.local",
            hash="$krb5tgs$...",
            encryption="AES256",
            hashcat_mode=HashcatMode.KERBEROS_AES256,
            hostname="web.corp.local",
            timestamp="2026-06-19T14:00:00+00:00",
        )
        result = KerberosScanResult(
            domain="corp.local",
            dc_ip="10.0.0.1",
            mode="all",
            kerberoast_hashes=[h],
        )
        out = tmp_path / "kerberoast.json"
        scanner.to_json(result, str(out))
        data = json.loads(out.read_text())
        assert len(data["kerberoast_hashes"]) == 1
        assert data["kerberoast_hashes"][0]["username"] == "svc-http"
        assert data["kerberoast_hashes"][0]["hashcat_mode"] == "19800"


# ---------------------------------------------------------------------------
# scan() dispatcher tests
# ---------------------------------------------------------------------------

class TestScanDispatcher:
    @patch.object(KerberosScanner, "scan_asreproast")
    @patch.object(KerberosScanner, "scan_kerberoast")
    @patch.object(KerberosScanner, "scan_delegation")
    def test_scan_all(
        self,
        mock_delegation: MagicMock,
        mock_kerberoast: MagicMock,
        mock_asreproast: MagicMock,
        scanner: KerberosScanner,
    ) -> None:
        mock_asreproast.return_value = KerberosScanResult(
            domain="lab.local", dc_ip="10.0.0.1", mode="all", asrep_hashes=[]
        )
        mock_kerberoast.return_value = KerberosScanResult(
            domain="lab.local", dc_ip="10.0.0.1", mode="all", kerberoast_hashes=[]
        )
        mock_delegation.return_value = KerberosScanResult(
            domain="lab.local", dc_ip="10.0.0.1", mode="all", delegation_findings=[]
        )
        result = scanner.scan(ScanMode.ALL)
        assert mock_asreproast.called
        assert mock_kerberoast.called
        assert mock_delegation.called

    @patch.object(KerberosScanner, "scan_asreproast")
    def test_scan_asreproast_mode(
        self, mock_asreproast: MagicMock, scanner: KerberosScanner
    ) -> None:
        mock_asreproast.return_value = KerberosScanResult(
            domain="lab.local", dc_ip="10.0.0.1", mode="asreproast"
        )
        result = scanner.scan(ScanMode.ASREPROAST)
        assert mock_asreproast.called
        assert "asreproast" in result.mode


# ---------------------------------------------------------------------------
# Logging / defensive tests
# ---------------------------------------------------------------------------

class TestLogging:
    def test_logger_configured(self, scanner: KerberosScanner) -> None:
        assert scanner.logger is not None
        assert scanner.logger.name.endswith("kerberos_scanner")

    def test_no_shell_injection_in_command(self, scanner: KerberosScanner) -> None:
        """Confirm subprocess calls use list form, not shell=True."""
        import inspect

        src = inspect.getsource(KerberosScanner)
        assert "shell=True" not in src

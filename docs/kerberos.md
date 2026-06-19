# Kerberos Scanner — Documentation

> Read-only audit module. No lateral movement or exploitation code.

## 1. Overview

The `KerberosScanner` module provides three production-ready audit capabilities:

| Mode | Impacket Tool | Hashcat Mode | What it finds |
|------|---------------|--------------|---------------|
| **ASREPRoast** | `GetNPUsers.py` | **18200** | Accounts with `DONT_REQUIRE_PREAUTH` |
| **Kerberoast** | `GetUserSPNs.py` | **13100** (RC4), **19700** (AES128), **19800** (AES256) | Accounts with SPNs (service accounts) |

Plus a **Delegation Audit** via LDAP that computer accounts are at risk (unconstrained, constrained, RBCD).

### Directory layout

```
~/pentest/projects/ai-security-tools/
├── src/kerberos_scanner.py
├── docs/kerberos.md            ← this file
├── examples/kerberos_scan_example.json
├── tests/test_kerberos_scanner.py
├── pyproject.toml              ← scanner entry point
├── README.md                   ← Kerberos section
```

Default output directory: `~/pentest/results/kerberos/`
Default log file: `~/pentest/logs/kerberos_scanner.log`

---

## 2. Installation

### 2.1 Python dependencies

The scanner needs **Impacket**, **ldap3**, and standard Py3.10+ tooling. From the project root:

```bash
cd ~/pentest/projects/ai-security-tools

# Option A: uv sync (PEP 668 friendly)
uv sync --extra kerberos

# Option B: pip in a venv
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[kerberos]"
```

### 2.2 System Impacket (Kali recommended)

For reliability on Kali, also install the OS package:

```bash
sudo apt update && sudo apt install -y python3-impacket
```

Verify:

```bash
impacket-GetNPUsers.py -h | head
impacket-GetUserSPNs.py -h | head
```

### 2.3 Config file

Create `~/pentest/config/api_keys.conf` (YAML):

```yaml
kerberos_scanner:
  domain: "corp.local"
  dc_ip: "10.0.0.1"
  username: "lowpriv"
  password: "P@ssw0rd!"
  ccache: ""            # optional: set path to ccache file instead of user/pass
  user_file: ""         # optional: text file with usernames (one per line) for ASREPRoast
  output_dir: "~/pentest/results/kerberos"
```

Or use environment variables:

```bash
export KERB_DOMAIN=corp.local
export KERB_DC_IP=10.0.0.1
export KERB_USERNAME=lowpriv
export KERB_PASSWORD=P@ssw0rd
```

---

## 3. Usage

### 3.1 Python API

```python
from pathlib import Path
from src.kerberos_scanner import KerberosScanner, ScanMode

# Initialize with config
scanner = KerberosScanner(
    config_path="~/pentest/config/api_keys.conf",
    output_dir="~/pentest/results/kerberos",
)

# Single mode
asrep = scanner.scan_asreproast()
print(scanner.to_table(asrep))
scanner.to_json(asrep, "~/pentest/results/kerberos/asrep.json")

kerb = scanner.scan_kerberoast()
print(scanner.to_table(kerb))
scanner.to_json(kerb, "~/pentest/results/kerberos/kerberoast.json")

delegation = scanner.scan_delegation()
print(scanner.to_table(delegation))
scanner.to_json(delegation, "~/pentest/results/kerberos/delegation.json")

# Run all modes
all_result = scanner.scan(ScanMode.ALL)
```

### 3.2 CLI

```bash
# From the project root (after pip install -e .)
python -m src.kerberos_scanner                   # run all modes
python -m src.kerberos_scanner asreproast        # ASREPRoast only
python -m src.kerberos_scanner kerberoast        # Kerberoast only
python -m src.kerberos_scanner delegation        # Delegation audit

# Override config via flags
python -m src.kerberos_scanner kerberoast \
  --dc-ip 10.0.0.1 \
  --domain corp.local \
  --username user \
  --password pass \
  --user-file ~/pentest/wordlists/ad_usernames_wordlist.txt \
  --json-out ~/pentest/results/kerberoast_lab.json
```

### 3.3 With ccache (Kerberos auth)

```bash
export KRB5CCNAME=/tmp/krb5cc_user
python -m src.kerberos_scanner kerberoast --ccache /tmp/krb5cc_user
```

### 3.4 Targeted user list for ASREPRoast

```bash
python -m src.kerberos_scanner asreproast \
  --user-file ~/pentest/wordlists/ad_usernames_wordlist.txt
```

---

## 4. Output Format — JSON

Each scan mode produces a JSON file with the following structure:

```jsonc
{
  "domain": "corp.local",
  "dc_ip": "10.0.0.1",
  "mode": "kerberoast",
  "asrep_hashes": [],
  "kerberoast_hashes": [
    {
      "username": "svc-sql",
      "spn": "MSSQLSvc/sql01.corp.local:1433",
      "hash": "$krb5tgs$23$*user$MSSQLSvc/sql01...LONGHASH",
      "encryption": "RC4-HMAC",
      "hashcat_mode": "13100",
      "hostname": "sql01.corp.local",
      "timestamp": "2026-06-19T..."
    }
  ],
  "delegation_findings": [],
  "scan_errors": [],
  "scan_metadata": {
    "output_file": "...",
    "hashcat_modes": { "rc4": "13100", "aes128": "19700", "aes256": "19800" },
    "total_spns_found": 3,
    "impacket_tool": "GetUserSPNs.py"
  }
}
```

---

## 5. Hashcat Reference

| Attack | Hashcat Mode | Example |
|--------|--------------|---------|
| ASREPRoast | `18200` | `hashcat -m 18200 asrep_hashes.txt rockyou.txt --force` |
| Kerberoast RC4-HMAC | `13100` | `hashcat -m 13100 tgs_rc4.txt rockyou.txt --force` |
| Kerberoast AES128 | `19700` | `hashcat -m 19700 tgs_aes128.txt rockyou.txt --force` |
| Kerberoast AES256 | `19800` | `hashcat -m 19800 tgs_aes256.txt rockyou.txt --force` |

---

## 6. Delegation Audit Reference

| Flag | Value | Meaning |
|------|-------|---------|
| `TRUSTED_FOR_DELEGATION` | `0x80000` (524288) | Unconstrained Delegation — **CRITICAL** |
| `TRUSTED_TO_AUTH_FOR_DELEGATION` | `0x1000000` (16777216) | Constrained Delegation with Protocol Transition |

Additional check: `msDS-AllowedToDelegateTo` attribute (what services the account can delegate to).
Additional check: `msDS-AllowedToActOnBehalfOfOtherIdentity` (RBCD — Resource-Based Constrained Delegation).

### Remediation

- Remove Unconstrained Delegation from member servers.
- Restrict Constrained Delegation to specific SPNs.
- Prevent RBCD abuse — monitor write access to computer accounts.
- Place high-value accounts in the Protected Users group (disables delegation).

---

## 7. Error Handling

- **LDAP timeout / unreachable DC**: Returns partial result with `scan_errors` populated.
- **Missing Impacket**: Graceful error message guiding install instructions.
- **Missing ldap3**: Graceful error — delegation mode skipped, other modes still work.
- **No AS-REP / no SPNs found**: Empty list, exit 0 (no findings is a valid result).
- **Invalid domain/credentials**: LDAP bind failure captured in `scan_errors`.

---

## 8. Logging

All activity is logged to `~/pentest/logs/kerberos_scanner.log` at DEBUG level, plus INFO to stderr.

```bash
tail -f ~/pentest/logs/kerberos_scanner.log
```

---

## 9. Security Notes

- **No lateral movement**: This module reads directory data and requests tickets; it never executes against services or performs pass-the-hash, DCSync, etc.
- **No hardcoded secrets**: All credentials loaded from config file or environment.
- **No shell injection**: Uses `subprocess.run([...])` with list args (no `shell=True`).
- **Validate inputs**: Domain, DC IP, and username are passed through Impacket's validated argument parsing.
- **Log redaction**: Username is truncated in metadata (`user***`) to avoid credential exposure in logs.

---

## 10. Troubleshooting

| Issue | Fix |
|-------|-----|
| `impacket-GetNPUsers.py: command not found` | `pip install impacket` or `sudo apt install python3-impacket` |
| `ldap3 not installed` | `pip install ldap3` |
| `Connection refused` | Check DC IP, firewall, network access |
| `Invalid credentials` (LDAP bind fail) | Verify username/password or ccache path |
| `No users with AS-REP found` | Not all accounts have `DONT_REQUIRE_PREAUTH` — this is expected |
| `No SPNs found` | Domain may not have service accounts with SPNs |

---

## 11. Extending

To add a new scan mode:

1. Create a `scan_<mode>()` method returning `KerberosScanResult`.
2. Register it in the `scan()` dispatcher loop under `ScanMode`.
3. Add terminal table formatting in `to_table()`.
4. Add JSON structure in `KerberosScanResult.to_dict()`.

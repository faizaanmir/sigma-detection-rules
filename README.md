# Sigma Detection Rules

Vendor-agnostic detection rules written in the [Sigma](https://github.com/SigmaHQ/sigma) format. Sigma rules can be converted to KQL (Microsoft Sentinel), SPL (Splunk), AQL (IBM QRadar), Elasticsearch, and many other SIEM query languages using `sigma-cli`.

---

## Why Sigma?

Writing detections in Sigma means one rule works across all SIEM platforms. Instead of maintaining separate KQL, SPL, and AQL versions of the same detection, you write it once and convert.

---

## Rule Index

| Rule | Tactic | Technique | Severity |
|---|---|---|---|
| [ntlm-password-spray.yml](credential-access/ntlm-password-spray.yml) | Credential Access | T1110.003 | High |
| [dcsync-attack.yml](credential-access/dcsync-attack.yml) | Credential Access | T1003.006 | Critical |
| [phishing-office-spawning-shell.yml](initial-access/phishing-office-spawning-shell.yml) | Initial Access | T1566.001 | High |
| [scheduled-task-creation-cli.yml](persistence/scheduled-task-creation-cli.yml) | Persistence | T1053.005 | Medium |
| [smb-admin-share-access.yml](lateral-movement/smb-admin-share-access.yml) | Lateral Movement | T1021.002 | High |
| [dns-high-query-volume.yml](exfiltration/dns-high-query-volume.yml) | Exfiltration | T1048.003 | Medium |
| [powershell-encoded-command.yml](defense-evasion/powershell-encoded-command.yml) | Defense Evasion | T1059.001 | High |
| [lolbas-mshta-execution.yml](defense-evasion/lolbas-mshta-execution.yml) | Defense Evasion | T1218.005 | High |

---

## Converting Rules

### Install sigma-cli

```bash
pip install sigma-cli
pip install pysigma-backend-splunk
pip install pysigma-backend-microsoft365defender
pip install pysigma-backend-qradar
```

### Convert to Splunk SPL

```bash
sigma convert -t splunk -p splunk_windows credential-access/ntlm-password-spray.yml
```

### Convert to KQL (Microsoft Sentinel)

```bash
sigma convert -t microsoft365defender credential-access/ntlm-password-spray.yml
```

### Convert to QRadar AQL

```bash
sigma convert -t qradar credential-access/ntlm-password-spray.yml
```

### Bulk convert entire folder

```bash
sigma convert -t splunk -p splunk_windows credential-access/ -o output_splunk/
```

---

## Rule Structure

Each `.yml` file follows the official Sigma schema:

```yaml
title:          Human-readable rule name
id:             UUID
status:         stable | test | experimental
description:    What the rule detects and why it matters
author:         Faizaan Sajjad
date:           YYYY-MM-DD
tags:
    - attack.tactic_name
    - attack.tXXXX
logsource:
    category:   process_creation | dns | network_connection | ...
    product:    windows | linux | ...
detection:
    selection:
        field: value
    condition:  selection
falsepositives:
    - Known false positive sources
level:          critical | high | medium | low | informational
```

---

## References

- [Sigma GitHub](https://github.com/SigmaHQ/sigma)
- [Sigma Rule Hub](https://sigmahq.io/)
- [sigma-cli documentation](https://github.com/SigmaHQ/sigma-cli)
- [MITRE ATT&CK](https://attack.mitre.org/)

---

*Author: Faizaan Sajjad — Security Specialist, Orange Cyber Defense*
*All rules use sanitized data. Test in your environment before production deployment.*

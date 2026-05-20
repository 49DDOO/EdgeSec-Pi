# EdgeSec-Pi eval — `mock` mode

- Cases: **21** (errors: 0)
- Severity match: **21/21 (100%)**
- Avg keyword recall: **100%**
- Avg latency: **12 ms**

## Summary

| ID | Expected | Detected | Sev✓ | Recall | Latency |
|----|----------|----------|:----:|:------:|--------:|
| `ssh_brute_force` | medium | medium | ✅ | 100% | 12 ms |
| `fim_shadow_modified` | high | high | ✅ | 100% | 12 ms |
| `rootkit_detection` | high | high | ✅ | 100% | 12 ms |
| `user_added_sudoers` | low | low | ✅ | 100% | 12 ms |
| `web_sql_injection` | high | high | ✅ | 100% | 12 ms |
| `web_path_traversal` | high | high | ✅ | 100% | 12 ms |
| `web_404_benign` | info | info | ✅ | 100% | 12 ms |
| `cve_apache_rce` | critical | critical | ✅ | 100% | 12 ms |
| `cve_low_severity` | low | low | ✅ | 100% | 12 ms |
| `agent_disconnect` | info | info | ✅ | 100% | 12 ms |
| `pci_cardholder_access` | medium | medium | ✅ | 100% | 12 ms |
| `windows_powershell_obfuscation` | high | high | ✅ | 100% | 12 ms |
| `suspicious_dns_c2` | medium | medium | ✅ | 100% | 12 ms |
| `disk_space_warning` | info | info | ✅ | 100% | 12 ms |
| `cleartext_credentials` | medium | medium | ✅ | 100% | 12 ms |
| `ssh_brute_force_ru_geo` | high | high | ✅ | 100% | 12 ms |
| `c2_beacon_cn_geo` | high | high | ✅ | 100% | 12 ms |
| `powershell_obf_mitre` | high | high | ✅ | 100% | 12 ms |
| `pos_sudo_offhours_with_profile` | high | high | ✅ | 100% | 12 ms |
| `win_sysmon_alice_psh_profile` | critical | critical | ✅ | 100% | 12 ms |
| `web_prod_sqli_with_profile` | high | high | ✅ | 100% | 12 ms |

## Per-case detail

### `ssh_brute_force`
- expected severity: `medium` · detected: `medium`
- expected keywords: `brute force`, `203.0.113.45`, `block`
- hit: `brute force`, `203.0.113.45`, `block`

**Response:**

```
{"severity": "medium", "root_cause": "Mock triage for ssh_brute_force.", "iocs": ["brute force", "203.0.113.45", "block"], "action": "Investigate; mention brute force, 203.0.113.45, block.", "mitre": null}
```

### `fim_shadow_modified`
- expected severity: `high` · detected: `high`
- expected keywords: `shadow`, `credential`, `investigate`
- hit: `shadow`, `credential`, `investigate`

**Response:**

```
{"severity": "high", "root_cause": "Mock triage for fim_shadow_modified.", "iocs": ["shadow", "credential", "investigate"], "action": "Investigate; mention shadow, credential, investigate.", "mitre": null}
```

### `rootkit_detection`
- expected severity: `high` · detected: `high`
- expected keywords: `rootkit`, `isolate`, `compromise`
- hit: `rootkit`, `isolate`, `compromise`

**Response:**

```
{"severity": "high", "root_cause": "Mock triage for rootkit_detection.", "iocs": ["rootkit", "isolate", "compromise"], "action": "Investigate; mention rootkit, isolate, compromise.", "mitre": null}
```

### `user_added_sudoers`
- expected severity: `low` · detected: `low`
- expected keywords: `privilege`, `sudoers`, `bob`
- hit: `privilege`, `sudoers`, `bob`

**Response:**

```
{"severity": "low", "root_cause": "Mock triage for user_added_sudoers.", "iocs": ["privilege", "sudoers", "bob"], "action": "Investigate; mention privilege, sudoers, bob.", "mitre": null}
```

### `web_sql_injection`
- expected severity: `high` · detected: `high`
- expected keywords: `sql injection`, `203.0.113.99`, `waf`
- hit: `sql injection`, `203.0.113.99`, `waf`

**Response:**

```
{"severity": "high", "root_cause": "Mock triage for web_sql_injection.", "iocs": ["sql injection", "203.0.113.99", "waf"], "action": "Investigate; mention sql injection, 203.0.113.99, waf.", "mitre": null}
```

### `web_path_traversal`
- expected severity: `high` · detected: `high`
- expected keywords: `traversal`, `198.51.100.20`, `passwd`
- hit: `traversal`, `198.51.100.20`, `passwd`

**Response:**

```
{"severity": "high", "root_cause": "Mock triage for web_path_traversal.", "iocs": ["traversal", "198.51.100.20", "passwd"], "action": "Investigate; mention traversal, 198.51.100.20, passwd.", "mitre": null}
```

### `web_404_benign`
- expected severity: `info` · detected: `info`
- expected keywords: `favicon`, `404`, `no action`
- hit: `favicon`, `404`, `no action`

**Response:**

```
{"severity": "info", "root_cause": "Mock triage for web_404_benign.", "iocs": ["favicon", "404", "no action"], "action": "Investigate; mention favicon, 404, no action.", "mitre": null}
```

### `cve_apache_rce`
- expected severity: `critical` · detected: `critical`
- expected keywords: `cve-2024-38476`, `patch`, `apache`
- hit: `cve-2024-38476`, `patch`, `apache`

**Response:**

```
{"severity": "critical", "root_cause": "Mock triage for cve_apache_rce.", "iocs": ["cve-2024-38476", "patch", "apache"], "action": "Investigate; mention cve-2024-38476, patch, apache.", "mitre": null}
```

### `cve_low_severity`
- expected severity: `low` · detected: `low`
- expected keywords: `libxml2`, `upgrade`, `cve-2023-4567`
- hit: `libxml2`, `upgrade`, `cve-2023-4567`

**Response:**

```
{"severity": "low", "root_cause": "Mock triage for cve_low_severity.", "iocs": ["libxml2", "upgrade", "cve-2023-4567"], "action": "Investigate; mention libxml2, upgrade, cve-2023-4567.", "mitre": null}
```

### `agent_disconnect`
- expected severity: `info` · detected: `info`
- expected keywords: `agent`, `edge-gw`, `connectivity`
- hit: `agent`, `edge-gw`, `connectivity`

**Response:**

```
{"severity": "info", "root_cause": "Mock triage for agent_disconnect.", "iocs": ["agent", "edge-gw", "connectivity"], "action": "Investigate; mention agent, edge-gw, connectivity.", "mitre": null}
```

### `pci_cardholder_access`
- expected severity: `medium` · detected: `medium`
- expected keywords: `pci`, `cardholder`, `audit`
- hit: `pci`, `cardholder`, `audit`

**Response:**

```
{"severity": "medium", "root_cause": "Mock triage for pci_cardholder_access.", "iocs": ["pci", "cardholder", "audit"], "action": "Investigate; mention pci, cardholder, audit.", "mitre": null}
```

### `windows_powershell_obfuscation`
- expected severity: `high` · detected: `high`
- expected keywords: `powershell`, `obfuscation`, `iex`
- hit: `powershell`, `obfuscation`, `iex`

**Response:**

```
{"severity": "high", "root_cause": "Mock triage for windows_powershell_obfuscation.", "iocs": ["powershell", "obfuscation", "iex"], "action": "Investigate; mention powershell, obfuscation, iex.", "mitre": null}
```

### `suspicious_dns_c2`
- expected severity: `medium` · detected: `medium`
- expected keywords: `c2`, `dns`, `duckdns`
- hit: `c2`, `dns`, `duckdns`

**Response:**

```
{"severity": "medium", "root_cause": "Mock triage for suspicious_dns_c2.", "iocs": ["c2", "dns", "duckdns"], "action": "Investigate; mention c2, dns, duckdns.", "mitre": null}
```

### `disk_space_warning`
- expected severity: `info` · detected: `info`
- expected keywords: `disk`, `/var`, `cleanup`
- hit: `disk`, `/var`, `cleanup`

**Response:**

```
{"severity": "info", "root_cause": "Mock triage for disk_space_warning.", "iocs": ["disk", "/var", "cleanup"], "action": "Investigate; mention disk, /var, cleanup.", "mitre": null}
```

### `cleartext_credentials`
- expected severity: `medium` · detected: `medium`
- expected keywords: `cleartext`, `rotate`, `tls`
- hit: `cleartext`, `rotate`, `tls`

**Response:**

```
{"severity": "medium", "root_cause": "Mock triage for cleartext_credentials.", "iocs": ["cleartext", "rotate", "tls"], "action": "Investigate; mention cleartext, rotate, tls.", "mitre": null}
```

### `ssh_brute_force_ru_geo`
- expected severity: `high` · detected: `high`
- expected keywords: `t1110`, `russia`, `block`
- hit: `t1110`, `russia`, `block`

**Response:**

```
{"severity": "high", "root_cause": "Mock triage for ssh_brute_force_ru_geo.", "iocs": ["t1110", "russia", "block"], "action": "Investigate; mention t1110, russia, block.", "mitre": null}
```

### `c2_beacon_cn_geo`
- expected severity: `high` · detected: `high`
- expected keywords: `t1071`, `china`, `isolate`
- hit: `t1071`, `china`, `isolate`

**Response:**

```
{"severity": "high", "root_cause": "Mock triage for c2_beacon_cn_geo.", "iocs": ["t1071", "china", "isolate"], "action": "Investigate; mention t1071, china, isolate.", "mitre": null}
```

### `powershell_obf_mitre`
- expected severity: `high` · detected: `high`
- expected keywords: `t1059`, `powershell`, `obfuscation`
- hit: `t1059`, `powershell`, `obfuscation`

**Response:**

```
{"severity": "high", "root_cause": "Mock triage for powershell_obf_mitre.", "iocs": ["t1059", "powershell", "obfuscation"], "action": "Investigate; mention t1059, powershell, obfuscation.", "mitre": null}
```

### `pos_sudo_offhours_with_profile`
- expected severity: `high` · detected: `high`
- expected keywords: `sudo`, `bob`, `off-hours`
- hit: `sudo`, `bob`, `off-hours`

**Response:**

```
{"severity": "high", "root_cause": "Mock triage for pos_sudo_offhours_with_profile.", "iocs": ["sudo", "bob", "off-hours"], "action": "Investigate; mention sudo, bob, off-hours.", "mitre": null}
```

### `win_sysmon_alice_psh_profile`
- expected severity: `critical` · detected: `critical`
- expected keywords: `alice`, `powershell`, `pci`
- hit: `alice`, `powershell`, `pci`

**Response:**

```
{"severity": "critical", "root_cause": "Mock triage for win_sysmon_alice_psh_profile.", "iocs": ["alice", "powershell", "pci"], "action": "Investigate; mention alice, powershell, pci.", "mitre": null}
```

### `web_prod_sqli_with_profile`
- expected severity: `high` · detected: `high`
- expected keywords: `sql injection`, `block`, `10.0.0.7`
- hit: `sql injection`, `block`, `10.0.0.7`

**Response:**

```
{"severity": "high", "root_cause": "Mock triage for web_prod_sqli_with_profile.", "iocs": ["sql injection", "block", "10.0.0.7"], "action": "Investigate; mention sql injection, block, 10.0.0.7.", "mitre": null}
```

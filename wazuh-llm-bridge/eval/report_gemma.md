# EdgeSec-Pi eval — `live` mode

- Cases: **15** (errors: 0)
- Severity match: **11/15 (73%)**
- Avg keyword recall: **82%**
- Avg latency: **15734 ms**

## Summary

| ID | Expected | Detected | Sev✓ | Recall | Latency |
|----|----------|----------|:----:|:------:|--------:|
| `ssh_brute_force` | high | high | ✅ | 100% | 27496 ms |
| `fim_shadow_modified` | critical | critical | ✅ | 33% | 14016 ms |
| `rootkit_detection` | critical | critical | ✅ | 67% | 15910 ms |
| `user_added_sudoers` | high | critical | ❌ | 100% | 15513 ms |
| `web_sql_injection` | high | high | ✅ | 67% | 15615 ms |
| `web_path_traversal` | high | high | ✅ | 100% | 15523 ms |
| `web_404_benign` | info | info | ✅ | 100% | 11882 ms |
| `cve_apache_rce` | critical | high | ❌ | 100% | 17474 ms |
| `cve_low_severity` | low | low | ✅ | 67% | 12718 ms |
| `agent_disconnect` | medium | medium | ✅ | 100% | 14281 ms |
| `pci_cardholder_access` | high | critical | ❌ | 100% | 15950 ms |
| `windows_powershell_obfuscation` | high | high | ✅ | 67% | 15404 ms |
| `suspicious_dns_c2` | medium | high | ❌ | 100% | 17115 ms |
| `disk_space_warning` | info | info | ✅ | 33% | 11501 ms |
| `cleartext_credentials` | high | high | ✅ | 100% | 15615 ms |

## Per-case detail

### `ssh_brute_force`
- expected severity: `high` · detected: `high`
- expected keywords: `brute force`, `203.0.113.45`, `block`
- hit: `brute force`, `203.0.113.45`, `block`

**Response:**

```
{
  "severity": "high",
  "summary_zh": "有人從外部網路嘗試使用不存在的管理員帳號多次強行登入您的伺服器。",
  "impact_zh": "如果對方成功猜中密碼，可能會非法進入系統竊取公司機密資料或植入惡意軟體。",
  "next_step_zh": "請指示 IT 人員立即封鎖該外部 IP 位址，並檢查是否有任何登入成功的紀錄。",
  "root_cause": "SSH brute force attack targeting invalid user 'admin' from external IP.",
  "iocs": [
    "203.0.113.45"
  ],
  "action": "Block source IP 203.0.113.45 at the firewall and disable password authentication for SSH in favor of SSH keys.",
  "mitre": "T1110",
  "needs_investigation": true,
  "investigation_reason": "Check SIEM logs for successful logins from this IP or other targeted accounts to determine if the attack succeeded."
}
```

### `fim_shadow_modified`
- expected severity: `critical` · detected: `critical`
- expected keywords: `shadow`, `credential`, `investigate`
- hit: `shadow`

**Response:**

```
{
  "severity": "critical",
  "summary_zh": "系統中儲存使用者密碼的核心檔案被修改了。",
  "impact_zh": "攻擊者可能已經取得了最高權限，可以隨意更改密碼或竊取所有帳號資訊。",
  "next_step_zh": "請立即要求 IT 人員檢查誰修改了該檔案，並確認系統是否已被入侵。",
  "root_cause": "Unauthorized modification of /etc/shadow detected via FIM checksum change.",
  "iocs": [
    "/etc/shadow"
  ],
  "action": "Audit auth logs for unauthorized sudo usage and verify the integrity of all root-level accounts.",
  "mitre": "T1098",
  "needs_investigation": true,
  "investigation_reason": "Need to correlate FIM event with auditd logs to identify the process and user responsible for the modification."
}
```

### `rootkit_detection`
- expected severity: `critical` · detected: `critical`
- expected keywords: `rootkit`, `isolate`, `compromise`
- hit: `rootkit`, `isolate`

**Response:**

```
{
  "severity": "critical",
  "summary_zh": "系統偵測到伺服器被植入了惡意隱藏程式，這是一種極高風險的駭客後門。",
  "impact_zh": "攻擊者可以完全控制您的伺服器，隨意讀取、修改或刪除公司所有機密資料。",
  "next_step_zh": "請立即指示 IT 人員將該伺服器從網路隔離，並重新安裝系統以確保完全清除。",
  "root_cause": "Detection of 'Suckit' rootkit via the presence of a hidden setuid binary at /sbin/.suckit.",
  "iocs": [
    "/sbin/.suckit"
  ],
  "action": "Isolate the host from the network, perform a forensic memory dump, and reinstall the OS from a known clean backup.",
  "mitre": "T1014",
  "needs_investigation": true,
  "investigation_reason": "Need to determine the initial entry vector and check for lateral movement or data exfiltration logs."
}
```

### `user_added_sudoers`
- expected severity: `high` · detected: `critical`
- expected keywords: `privilege`, `sudoers`, `bob`
- hit: `privilege`, `sudoers`, `bob`

**Response:**

```
{
  "severity": "critical",
  "summary_zh": "一名使用者將自己的帳號權限提升為最高管理員，可以完全控制這台資料庫伺服器。",
  "impact_zh": "如果這是未經授權的操作，攻擊者可以隨意刪除、修改或竊取公司所有資料。",
  "next_step_zh": "請立即要求 IT 確認該員工是否獲准執行此操作，若非授權則需立刻撤銷其權限並檢查系統。",
  "root_cause": "User 'bob' used sudo to add themselves to the sudoers group, granting permanent root-level privileges.",
  "iocs": [
    "bob"
  ],
  "action": "Verify authorization for the privilege escalation and remove 'bob' from the sudo group if unauthorized.",
  "mitre": "T1068",
  "needs_investigation": true,
  "investigation_reason": "Check if 'bob' is a legitimate admin or if the account was compromised to perform privilege escalation."
}
```

### `web_sql_injection`
- expected severity: `high` · detected: `high`
- expected keywords: `sql injection`, `203.0.113.99`, `waf`
- hit: `sql injection`, `203.0.113.99`

**Response:**

```
{
  "severity": "high",
  "summary_zh": "有人嘗試利用網站的搜尋功能來非法入侵您的資料庫。",
  "impact_zh": "如果攻擊成功，對方可能會竊取公司機密資料或刪除重要數據。",
  "next_step_zh": "請指示 IT 人員立即封鎖該外部 IP 地址，並檢查網站程式碼是否已修補漏洞。",
  "root_cause": "SQL injection attempt via the 'q' parameter in a GET request using a classic tautology payload.",
  "iocs": [
    "203.0.113.99"
  ],
  "action": "Block source IP 203.0.113.99 and implement parameterized queries or input validation on the /search endpoint.",
  "mitre": "T1190",
  "needs_investigation": true,
  "investigation_reason": "The server responded with HTTP 200; need to verify if the payload actually bypassed filters and leaked data."
}
```

### `web_path_traversal`
- expected severity: `high` · detected: `high`
- expected keywords: `traversal`, `198.51.100.20`, `passwd`
- hit: `traversal`, `198.51.100.20`, `passwd`

**Response:**

```
{
  "severity": "high",
  "summary_zh": "有人嘗試利用網站漏洞來偷看伺服器內部的系統設定檔。",
  "impact_zh": "如果攻擊成功，對方可能會獲取伺服器的使用者清單或其他敏感資訊，進而對系統進行更深層的攻擊。",
  "next_step_zh": "請 IT 人員立即封鎖該外部 IP 地址，並檢查網站程式碼是否正確限制了檔案存取路徑。",
  "root_cause": "Path traversal attempt targeting /etc/passwd via GET request.",
  "iocs": [
    "198.51.100.20"
  ],
  "action": "Block source IP at firewall and validate input sanitization on the web application to prevent directory traversal.",
  "mitre": "T1083",
  "needs_investigation": true,
  "investigation_reason": "Check logs for other requests from this IP to determine if any traversal attempts returned a 200 OK status."
}
```

### `web_404_benign`
- expected severity: `info` · detected: `info`
- expected keywords: `favicon`, `404`, `no action`
- hit: `favicon`, `404`, `no action`

**Response:**

```
{
  "severity": "info",
  "summary_zh": "網站伺服器記錄到一個找不到檔案的正常錯誤，通常是瀏覽器在尋找網站圖示。",
  "impact_zh": "這屬於正常的網路運作現象，對系統安全沒有影響。",
  "next_step_zh": "無需採取任何行動。",
  "root_cause": "Web server returned a 404 Not Found error for the /favicon.ico request.",
  "iocs": [
    "10.0.0.55"
  ],
  "action": "No action required; this is benign operational noise.",
  "mitre": null,
  "needs_investigation": false,
  "investigation_reason": ""
}
```

### `cve_apache_rce`
- expected severity: `critical` · detected: `high`
- expected keywords: `cve-2024-38476`, `patch`, `apache`
- hit: `cve-2024-38476`, `patch`, `apache`

**Response:**

```
{
  "severity": "high",
  "summary_zh": "公司伺服器使用的網頁軟體版本過舊，存在一個嚴重的安全漏洞。",
  "impact_zh": "駭客可能利用此漏洞直接控制伺服器，導致公司機密資料外洩或系統被癱瘓。",
  "next_step_zh": "請指示 IT 人員立即將網頁伺服器軟體更新至最新安全版本。",
  "root_cause": "Apache HTTP Server version 2.4.58 is vulnerable to CVE-2024-38476, allowing potential RCE or data leakage.",
  "iocs": [],
  "action": "Update httpd to the latest patched version (>= 2.4.59) via yum/dnf.",
  "mitre": "T1190",
  "needs_investigation": true,
  "investigation_reason": "Check web server access logs for patterns indicating exploitation attempts of CVE-2024-38476."
}
```

### `cve_low_severity`
- expected severity: `low` · detected: `low`
- expected keywords: `libxml2`, `upgrade`, `cve-2023-4567`
- hit: `libxml2`, `cve-2023-4567`

**Response:**

```
{
  "severity": "low",
  "summary_zh": "系統中發現一個舊版本的軟體元件存在輕微的安全漏洞。",
  "impact_zh": "雖然風險較低，但若被利用，可能會導致部分系統資訊外洩。",
  "next_step_zh": "請通知 IT 人員將該軟體元件更新至最新版本以修補漏洞。",
  "root_cause": "Outdated libxml2 package (version 2.9.13-3.el9) is vulnerable to CVE-2023-4567.",
  "iocs": [],
  "action": "Update libxml2 to the latest patched version via the system package manager.",
  "mitre": null,
  "needs_investigation": false,
  "investigation_reason": ""
}
```

### `agent_disconnect`
- expected severity: `medium` · detected: `medium`
- expected keywords: `agent`, `edge-gw`, `connectivity`
- hit: `agent`, `edge-gw`, `connectivity`

**Response:**

```
{
  "severity": "medium",
  "summary_zh": "一台名為 edge-gw 的網路設備與監控系統失去連線，目前無法得知其運行狀態。",
  "impact_zh": "如果設備發生故障或被攻擊，我們將無法第一時間收到警報，導致安全漏洞無法被發現。",
  "next_step_zh": "請 IT 人員立即檢查該設備是否正常開機，並確認監控軟體是否運作正常。",
  "root_cause": "Wazuh agent on host 'edge-gw' (007) stopped sending keepalive signals.",
  "iocs": [],
  "action": "Verify network connectivity to edge-gw and restart the wazuh-agent service.",
  "mitre": null,
  "needs_investigation": true,
  "investigation_reason": "Determine if the disconnection was caused by a system crash, network outage, or intentional termination by an attacker."
}
```

### `pci_cardholder_access`
- expected severity: `high` · detected: `critical`
- expected keywords: `pci`, `cardholder`, `audit`
- hit: `pci`, `cardholder`, `audit`

**Response:**

```
{
  "severity": "critical",
  "summary_zh": "系統偵測到有人存取存放信用卡資料的敏感檔案。",
  "impact_zh": "客戶的信用卡個資可能已經外流，會導致公司面臨法律責任與重大財務損失。",
  "next_step_zh": "請立即要求 IT 人員確認是誰在存取該檔案，並暫時切斷相關帳號的權限。",
  "root_cause": "Unauthorized or monitored access to a PCI-DSS sensitive file (/var/data/cards.csv) detected via auditd.",
  "iocs": [
    "/var/data/cards.csv"
  ],
  "action": "Identify the process and user associated with PID/UID 1000 and revoke access to cardholder data immediately.",
  "mitre": "T1530",
  "needs_investigation": true,
  "investigation_reason": "Need to correlate auditd logs with user session data to determine if this was a legitimate admin action or an active data exfiltration event."
}
```

### `windows_powershell_obfuscation`
- expected severity: `high` · detected: `high`
- expected keywords: `powershell`, `obfuscation`, `iex`
- hit: `powershell`, `iex`

**Response:**

```
{
  "severity": "high",
  "summary_zh": "系統偵測到有人嘗試執行一段經過偽裝的惡意指令，試圖從網路上下載並執行不明程式。",
  "impact_zh": "如果指令執行成功，駭客可以直接控制這台電腦，導致公司機密資料外洩或被植入勒索軟體。",
  "next_step_zh": "請 IT 人員立即隔離該台電腦，並檢查是否有異常的網路連線或新安裝的不明軟體。",
  "root_cause": "Execution of an obfuscated PowerShell script block using IEX to download and execute a remote payload.",
  "iocs": [],
  "action": "Isolate the affected host, terminate the PowerShell process, and analyze the destination URL if available in full logs.",
  "mitre": "T1059.001",
  "needs_investigation": true,
  "investigation_reason": "Need to identify the source of the script execution and determine if the remote payload was successfully downloaded."
}
```

### `suspicious_dns_c2`
- expected severity: `medium` · detected: `high`
- expected keywords: `c2`, `dns`, `duckdns`
- hit: `c2`, `dns`, `duckdns`

**Response:**

```
{
  "severity": "high",
  "summary_zh": "內部電腦正在嘗試連線到一個已知的惡意控制伺服器。",
  "impact_zh": "這通常代表電腦已被植入木馬或病毒，駭客可能正準備遠端操控您的系統或竊取公司資料。",
  "next_step_zh": "請立即指示 IT 人員將該台電腦斷網隔離，並檢查是否有異常程式在執行。",
  "root_cause": "Internal host 10.0.5.20 performed a DNS lookup for a known Command and Control (C2) domain via duckdns.org.",
  "iocs": [
    "kj4xmnq.duckdns.org",
    "10.0.5.20"
  ],
  "action": "Isolate the affected host from the network and perform a full malware scan and memory analysis to identify the malicious process.",
  "mitre": "T1071.004",
  "needs_investigation": true,
  "investigation_reason": "Need to identify the specific process initiating the DNS query and check for subsequent outbound traffic or lateral movement."
}
```

### `disk_space_warning`
- expected severity: `info` · detected: `info`
- expected keywords: `disk`, `/var`, `cleanup`
- hit: `/var`

**Response:**

```
{
  "severity": "info",
  "summary_zh": "伺服器的儲存空間快要滿了，目前已使用 84%。",
  "impact_zh": "如果空間完全被佔滿，系統可能會無法正常運作或導致服務中斷。",
  "next_step_zh": "請通知 IT 人員清理不需要的暫存檔案或增加儲存空間。",
  "root_cause": "The /var partition has exceeded the 80% usage threshold.",
  "iocs": [],
  "action": "Identify and remove large log files or expand the /var partition size.",
  "mitre": null,
  "needs_investigation": false,
  "investigation_reason": ""
}
```

### `cleartext_credentials`
- expected severity: `high` · detected: `high`
- expected keywords: `cleartext`, `rotate`, `tls`
- hit: `cleartext`, `rotate`, `tls`

**Response:**

```
{
  "severity": "high",
  "summary_zh": "系統偵測到有帳號密碼以不加密的方式在網路中傳輸，導致密碼直接外洩。",
  "impact_zh": "駭客若截獲這些資訊，可以直接使用該帳號登入系統並竊取財務或公司機密資料。",
  "next_step_zh": "請指示 IT 人員立即更改該帳號密碼，並將登入方式改為加密傳輸。",
  "root_cause": "Cleartext credentials (username/password) transmitted via unencrypted HTTP POST request to legacy.internal.",
  "iocs": [
    "svc-billing"
  ],
  "action": "Enforce HTTPS/TLS for the legacy.internal endpoint and rotate credentials for the svc-billing account.",
  "mitre": "T1040",
  "needs_investigation": true,
  "investigation_reason": "Check network logs to determine if this traffic originated from a compromised internal host or an unauthorized external source."
}
```

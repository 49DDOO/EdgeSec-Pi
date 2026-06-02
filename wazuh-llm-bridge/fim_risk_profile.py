"""Deterministic risk labels for Wazuh FIM file-change alerts."""
from __future__ import annotations

import re
from typing import Any


_DEFAULT_PROFILE: dict[str, Any] = {
    "category": "general_file_change",
    "risk_label_zh": "檔案被異動",
    "severity": "low",
    "business_meaning_zh": "這個檔案有變更，但目前不屬於內建高風險路徑。",
    "impact_zh": "若這不是預期維護，仍可能代表設定或資料被未授權修改。",
    "recommended_steps_zh": [
        "請確認這次異動是否為正常維護或軟體更新。",
        "若不是，請 IT 比對備份版本並檢查最近登入紀錄。",
    ],
    "it_checks": [
        "確認檔案變更時間是否符合維護紀錄。",
        "比對最近登入、sudo 或系統稽核紀錄。",
        "比對備份或版本控管中的上一版內容。",
    ],
}


_PROFILES: list[tuple[re.Pattern[str], dict[str, Any]]] = [
    (
        re.compile(r"^/etc/shadow$|^/etc/passwd$|^/etc/group$", re.I),
        {
            "category": "account_access",
            "risk_label_zh": "登入帳號核心檔案被修改",
            "severity": "high",
            "business_meaning_zh": "這類檔案控制系統帳號、群組或密碼資訊。",
            "impact_zh": "若不是正常維護，可能代表帳號被竄改、新增後門帳號，或登入權限被改變。",
            "recommended_steps_zh": [
                "請系統負責人確認是否有帳號維護或密碼政策變更。",
                "若沒有，請 IT 立即檢查最近登入、sudo、帳號新增與權限變更紀錄。",
                "確認未授權後，再依備份或設定管理系統恢復正確版本。",
            ],
            "it_checks": [
                "比對 /etc/passwd、/etc/shadow、/etc/group 的前後差異。",
                "檢查 sudo、ssh、PAM 與 auditd 紀錄。",
                "確認是否新增未知 UID 0 帳號或異常 shell。",
            ],
        },
    ),
    (
        re.compile(r"^/etc/sudoers$|^/etc/sudoers\.d/|^/private/etc/sudoers", re.I),
        {
            "category": "privilege_control",
            "risk_label_zh": "管理員權限設定被修改",
            "severity": "high",
            "business_meaning_zh": "這類檔案控制誰可以取得最高管理權限。",
            "impact_zh": "若被未授權修改，攻擊者可能取得系統最高權限並持續控制主機。",
            "recommended_steps_zh": [
                "請 IT 確認是否為授權的管理權限調整。",
                "若不是，請立即比對 sudoers 備份並檢查最近管理員登入紀錄。",
                "移除未知授權項目後，輪替受影響管理員帳號密碼。",
            ],
            "it_checks": [
                "執行 visudo -c 或平台等效檢查確認 sudoers 語法。",
                "比對 sudoers 與 sudoers.d 目錄前後差異。",
                "檢查最近 sudo、ssh、console login 紀錄。",
            ],
        },
    ),
    (
        re.compile(r"(^|/)\.ssh/authorized_keys$|^/etc/ssh/|^/private/etc/ssh/", re.I),
        {
            "category": "remote_access",
            "risk_label_zh": "遠端登入權限檔案被修改",
            "severity": "high",
            "business_meaning_zh": "這類檔案控制 SSH 遠端登入與金鑰授權。",
            "impact_zh": "若被未授權修改，可能有人新增可長期登入的後門金鑰。",
            "recommended_steps_zh": [
                "請確認是否有正常新增 SSH key 或調整 SSH 設定。",
                "若沒有，請 IT 移除未知金鑰並檢查最近 SSH 登入來源。",
                "檢查同一帳號是否在其他主機也被新增授權金鑰。",
            ],
            "it_checks": [
                "比對 authorized_keys 前後差異。",
                "檢查 sshd_config 是否允許不安全登入方式。",
                "查詢最近 SSH login、failed login 與來源 IP。",
            ],
        },
    ),
    (
        re.compile(r"^/etc/cron|^/var/spool/cron|/crontab$|^/Library/LaunchDaemons/|^/Library/LaunchAgents/", re.I),
        {
            "category": "persistence",
            "risk_label_zh": "開機或排程常駐設定被修改",
            "severity": "high",
            "business_meaning_zh": "這類檔案會讓程式在開機、登入或固定時間自動執行。",
            "impact_zh": "若不是正常維護，可能代表惡意程式正在建立常駐後門。",
            "recommended_steps_zh": [
                "請 IT 確認是否為正常服務安裝或排程調整。",
                "若不是，請停用未知項目並檢查對應程式路徑。",
                "追查同時間是否有新檔案、登入或下載行為。",
            ],
            "it_checks": [
                "檢查 cron、systemd timer、LaunchDaemon 或 LaunchAgent 內容。",
                "確認自動執行目標檔案是否可信。",
                "比對近期檔案新增與程序執行紀錄。",
            ],
        },
    ),
    (
        re.compile(r"^/var/www/|^/srv/www/|/htdocs/|/public_html/|/wp-content/", re.I),
        {
            "category": "web_content",
            "risk_label_zh": "網站程式或內容被修改",
            "severity": "medium",
            "business_meaning_zh": "這類檔案會影響網站內容、後台程式或對外服務。",
            "impact_zh": "若不是正常發布，可能代表網站被竄改、植入 webshell，或被放入惡意內容。",
            "recommended_steps_zh": [
                "請網站負責人確認是否為正常上版。",
                "若不是，請 IT 比對版本控管並檢查是否有 webshell 或未知 PHP/JS 檔。",
                "必要時先下架受影響檔案，從可信版本重新部署。",
            ],
            "it_checks": [
                "比對 Git 或備份中的正式版本。",
                "檢查新出現的 PHP、JS、可執行檔與可疑上傳目錄。",
                "查 Web access log 是否有上傳、RCE 或 path traversal 痕跡。",
            ],
        },
    ),
    (
        re.compile(r"^/(bin|sbin|usr/bin|usr/sbin|usr/local/bin|usr/local/sbin)/", re.I),
        {
            "category": "system_binary",
            "risk_label_zh": "系統執行檔被修改",
            "severity": "high",
            "business_meaning_zh": "這類檔案是系統命令或服務執行檔。",
            "impact_zh": "若不是正常更新，可能代表系統工具被替換、植入後門或 rootkit 化。",
            "recommended_steps_zh": [
                "請 IT 確認是否為正常套件更新。",
                "若不是，請比對套件校驗值並檢查是否有 rootkit 跡象。",
                "高可信度異常時，建議隔離主機並準備重建系統。",
            ],
            "it_checks": [
                "使用套件管理器驗證檔案完整性。",
                "檢查同時間是否有 privilege escalation 或未知程序。",
                "從可信來源重新安裝受影響套件或重建主機。",
            ],
        },
    ),
]


def classify(path: str) -> dict[str, Any]:
    """Return a stable risk profile for a FIM path."""
    normalized = str(path or "").strip()
    for pattern, profile in _PROFILES:
        if pattern.search(normalized):
            return {**profile, "matched_pattern": pattern.pattern}
    return {**_DEFAULT_PROFILE, "matched_pattern": ""}

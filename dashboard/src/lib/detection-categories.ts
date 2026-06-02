import type {
  Alert,
  DetectionCategory,
  DetectionCategoryKey,
  DetectionCategorySettings,
  DetectionNoiseProfile,
} from "@/lib/types";

export const defaultDetectionCategories: DetectionCategory[] = [
  {
    key: "authentication",
    label_zh: "登入 / 帳號",
    description_zh: "登入失敗、暴力嘗試、權限與帳號異常。",
    detail_zh: "對應 Wazuh authentication、sshd、pam、Windows 4624/4625 等登入事件。適合用來發現暴力破解、異常帳號、非上班時間登入、權限濫用與帳號被猜測。",
  },
  {
    key: "sca",
    label_zh: "安全設定檢查",
    description_zh: "CIS/SCA 基準、系統設定、防火牆、自動更新等姿態檢查。",
    detail_zh: "對應 Wazuh SCA / CIS benchmark。這通常是設定姿態或合規缺口，不一定代表正在被攻擊；重點是把 rationale、remediation、checks 與 compliance 對應翻成 IT 可修復清單。",
  },
  {
    key: "vulnerability",
    label_zh: "漏洞訊號",
    description_zh: "CVE、弱點套件與修補版本。",
    detail_zh: "對應 Wazuh Vulnerability Detection。系統會依 CVE、CVSS、套件名稱、目前版本與資產重要性排序，適合形成修補優先級工作單。",
  },
  {
    key: "fim",
    label_zh: "檔案 / 設定異動",
    description_zh: "重要檔案、設定檔、登入金鑰、啟動項或網站檔案被新增、修改、刪除。",
    detail_zh: "對應 Wazuh FIM / syscheck。用來監控 critical files、configuration files、content files，例如帳號檔、sudoers、authorized_keys、啟動項、網站目錄與系統執行檔；若有 whodata，會顯示誰用什麼程序改了什麼。",
  },
  {
    key: "network",
    label_zh: "網路服務變動",
    description_zh: "開放 port、listening service 與網路盤點變動；量大時可關閉以降低 LLM 負載。",
    detail_zh: "對應網路盤點、netstat、listening port 與服務狀態變更。適合找出新開放的管理介面、未知服務、C2 連線跡象或非預期的對外連線。",
  },
  {
    key: "process",
    label_zh: "可疑程序 / 指令",
    description_zh: "PowerShell、shell、未知程序與可疑命令列。",
    detail_zh: "對應命令執行、PowerShell、shell、未知二進位、可疑參數與 MITRE T1059 類行為。適合判斷下載執行、橫向移動、權限提升或腳本濫用。",
  },
  {
    key: "malware",
    label_zh: "惡意程式 / 入侵跡象",
    description_zh: "惡意程式、rootkit、後門、C2 與入侵跡象。",
    detail_zh: "對應 rootcheck、malware、rootkit、後門、C2 與已知攻擊技術。這類事件通常要提高處理層級：先降低擴散風險，再保全證據並交由 IT 深查。",
  },
  {
    key: "system",
    label_zh: "端點 / 平台狀態",
    description_zh: "端點 Agent 連線、平台健康、磁碟與作業系統狀態。",
    detail_zh: "對應 Wazuh agent 連線、平台健康、磁碟、作業系統與監控能力狀態。它不一定是攻擊，但會影響是否能即時看見風險。",
  },
  {
    key: "compliance",
    label_zh: "合規 / 稽核",
    description_zh: "PCI、NIST、ISO 27001、SOC 2、GDPR 等控制要求與稽核對應事件。",
    detail_zh: "對應稽核控制、政策要求與證據留存，例如 PCI、NIST、ISO 27001、SOC 2、GDPR。重點是管理缺口、補強證據與例外追蹤。",
  },
  {
    key: "other",
    label_zh: "其他",
    description_zh: "尚未對應到上述分頁的 Wazuh 群組或自訂規則，例如一般 syslog/ossec 狀態、整合測試或低優先級錯誤。",
    detail_zh: "用來承接尚未歸類的 Wazuh 群組、自訂規則、整合測試或低優先級系統事件。後續可依實際事件再拆成新的類別。",
  },
];

export const defaultEnabledDetectionCategories = Object.fromEntries(
  defaultDetectionCategories.map((category) => [category.key, true])
) as Record<DetectionCategoryKey, boolean>;

export const defaultDetectionNoiseProfile: DetectionNoiseProfile = {
  noisy_categories: [],
  core_disabled: [],
  false_positive_suppression: true,
  warnings: [],
};

export function normalizedDetectionSettings(
  settings?: DetectionCategorySettings
): DetectionCategorySettings {
  const categories = settings?.categories?.length ? settings.categories : defaultDetectionCategories;
  return {
    categories,
    enabled: {
      ...defaultEnabledDetectionCategories,
      ...(settings?.enabled || {}),
    },
    presets: settings?.presets || [],
    active_preset: settings?.active_preset || "custom",
    noise: settings?.noise || defaultDetectionNoiseProfile,
    message: settings?.message,
  };
}

function textForAlert(alert: Alert) {
  return [
    alert.rule_id,
    alert.rule_description,
    alert.summary,
    alert.business_impact,
    alert.root_cause,
    alert.technical_action,
    alert.full_log,
    alert.technical_evidence?.module,
    ...(alert.technical_evidence?.rule?.groups || []),
    ...(alert.iocs || []),
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
}

export function categoryForAlert(alert: Alert): DetectionCategoryKey {
  const evidenceModule = alert.technical_evidence?.module;
  if (evidenceModule === "authentication") return "authentication";
  if (evidenceModule === "sca") return "sca";
  if (evidenceModule === "vulnerability") return "vulnerability";
  if (evidenceModule === "fim") return "fim";
  if (evidenceModule === "syscollector") return "network";
  if (evidenceModule === "rootcheck") return "malware";

  const text = textForAlert(alert);
  if (/sca|cis|benchmark|安全設定|configuration baseline/.test(text)) return "sca";
  if (/pci|nist|iso ?27001|iso ?27002|soc ?2|gdpr|hipaa|compliance|稽核|合規/.test(text)) return "compliance";
  if (/cve|vulnerab|漏洞|patch|upgrade/.test(text)) return "vulnerability";
  if (/fim|syscheck|file|檔案|modified|changed|checksum|registry|登錄/.test(text)) return "fim";
  if (/login|登入|password|brute|ssh|rdp|authentication|帳號|4625|4624/.test(text)) {
    return "authentication";
  }
  if (/netstat|listening|opened ports?|port status|network|網路連接|連接埠/.test(text)) {
    return "network";
  }
  if (/powershell|script|command|process|exec|程序|指令|t1059/.test(text)) return "process";
  if (/malware|rootkit|trojan|backdoor|c2|intrusion|attack|惡意|入侵|後門/.test(text)) {
    return "malware";
  }
  if (/agent|ossec|disk|filesystem|system|disconnect|keepalive|系統|磁碟/.test(text)) return "system";
  return "other";
}

export function categoryLabel(
  key: DetectionCategoryKey,
  categories = defaultDetectionCategories
) {
  return categories.find((category) => category.key === key)?.label_zh || key;
}

export function filterAlertsByEnabledCategories(
  alerts: Alert[],
  settings?: DetectionCategorySettings
) {
  const normalized = normalizedDetectionSettings(settings);
  return alerts.filter((alert) => normalized.enabled[categoryForAlert(alert)]);
}

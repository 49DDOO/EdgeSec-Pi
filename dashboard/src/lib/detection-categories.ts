import type { Alert, DetectionCategory, DetectionCategoryKey, DetectionCategorySettings } from "@/lib/types";

export const defaultDetectionCategories: DetectionCategory[] = [
  {
    key: "authentication",
    label_zh: "登入 / 帳號",
    description_zh: "登入失敗、暴力嘗試、權限與帳號異常。",
  },
  {
    key: "sca",
    label_zh: "安全設定檢查",
    description_zh: "CIS/SCA 基準、系統設定、防火牆、自動更新等姿態檢查。",
  },
  {
    key: "vulnerability",
    label_zh: "漏洞偵測",
    description_zh: "CVE、弱點套件與修補版本。",
  },
  {
    key: "fim",
    label_zh: "檔案 / 設定異動",
    description_zh: "重要檔案、設定檔、登錄檔或權限異動。",
  },
  {
    key: "network",
    label_zh: "網路服務變動",
    description_zh: "開放 port、listening service 與網路盤點變動；量大時可關閉以降低 LLM 負載。",
  },
  {
    key: "process",
    label_zh: "可疑程序 / 指令",
    description_zh: "PowerShell、shell、未知程序與可疑命令列。",
  },
  {
    key: "malware",
    label_zh: "惡意程式 / 入侵跡象",
    description_zh: "惡意程式、rootkit、後門、C2 與入侵跡象。",
  },
  {
    key: "system",
    label_zh: "Agent / 平台狀態",
    description_zh: "Wazuh Agent 連線、平台健康、磁碟與作業系統狀態。",
  },
  {
    key: "compliance",
    label_zh: "合規 / 稽核",
    description_zh: "PCI、NIST、ISO 27001、SOC 2、GDPR 等控制要求與稽核對應事件。",
  },
  {
    key: "other",
    label_zh: "其他",
    description_zh: "尚未對應到上述分頁的 Wazuh 群組或自訂規則，例如一般 syslog/ossec 狀態、整合測試或低優先級錯誤。",
  },
];

export const defaultEnabledDetectionCategories = Object.fromEntries(
  defaultDetectionCategories.map((category) => [category.key, true])
) as Record<DetectionCategoryKey, boolean>;

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

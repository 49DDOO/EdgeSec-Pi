import { firstIpLike } from "@/lib/investigation";
import type { Alert } from "@/lib/types";
import type { ActionableAlertGroup } from "./actionable-alert-types";

// 將技術術語轉換成白話文
export const getPlainLanguageTitle = (alert: Alert) => {
  if (alert.summary) {
    return alert.summary;
  }
  const map: Record<string, string> = {
    "SSH 暴力破解嘗試": "有人嘗試入侵公司端點",
    "可疑檔案變更偵測": "重要檔案被修改了",
    "異常網路流量": "網路有異常傳輸",
    "防火牆規則變更": "防火牆設定被改動",
    "軟體漏洞偵測": "軟體有安全漏洞",
    "使用者權限提升": "員工權限被提升",
  };
  return map[alert.rule_description] || alert.rule_description;
};

// 業務影響的白話版
export const getPlainBusinessImpact = (alert: Alert) => {
  if (alert.business_impact) {
    return alert.business_impact;
  }
  const impactMap: Record<string, string> = {
    critical: "可能嚴重影響公司營運或資料安全",
    high: "可能影響部分業務或系統",
    medium: "需要留意但不緊急",
    low: "輕微問題，可安排時間處理",
  };
  return impactMap[alert.severity];
};

export const splitActionLines = (text?: string) => {
  return String(text || "")
    .split(/\n+/)
    .map((line) => line.replace(/^\s*\d+[.)、]\s*/, "").trim())
    .filter(Boolean);
};

export const isDocumentationIp = (value?: string) => {
  return /^(192\.0\.2|198\.51\.100|203\.0\.113)\.\d{1,3}$/.test(value || "");
};

export const getDecisionQuestion = (alert: Alert) => {
  const text = `${alert.rule_description} ${alert.summary} ${alert.root_cause}`;
  const sourceIp = firstIpLike(alert);
  const source = sourceIp ? `來源 ${sourceIp}` : "這次行為";
  if (/網路連接|連線|連接|port|listening|netstat|opened ports|network/i.test(text)) {
    return "請確認這台端點是否正在安裝、測試或啟動新服務。";
  }
  if (/登入|login|ssh|brute|password/i.test(text)) {
    return `請確認 ${source} 是否為公司允許的登入或測試。`;
  }
  if (/漏洞|CVE|vulnerab|upgrade|patch|更新/i.test(text)) {
    return "請確認這套軟體是否已安排更新；不確定時交給 IT 評估修補時間。";
  }
  if (/CIS|Benchmark|安全設定|configuration|SCA/i.test(text)) {
    return "請確認這項安全設定是否需要補強，或是否屬於公司允許的例外。";
  }
  if (/檔案|file|fim|modified|changed/i.test(text)) {
    return "請確認這次檔案或設定變更是否有人核准。";
  }
  return "請確認這件事是否為公司預期操作；不確定時交給 IT 查證。";
};

const alertGroupKey = (alert: Alert) => {
  const family = alert.rule_id || alert.rule_description || alert.summary;
  const actor = alert.source_ip || alert.iocs?.find((ioc) => /\b(?:\d{1,3}\.){3}\d{1,3}\b/.test(ioc)) || "";
  return [alert.agent_name, family, actor].join("|").toLowerCase();
};

export const groupPendingAlerts = (alerts: Alert[]): ActionableAlertGroup[] => {
  const groups = new Map<string, ActionableAlertGroup>();
  alerts
    .filter((alert) => alert.status === "pending")
    .forEach((alert) => {
      const key = alertGroupKey(alert);
      const current = groups.get(key);
      if (!current) {
        groups.set(key, { key, primary: alert, alerts: [alert] });
        return;
      }
      current.alerts.push(alert);
      if (new Date(alert.timestamp).getTime() > new Date(current.primary.timestamp).getTime()) {
        current.primary = alert;
      }
    });
  return Array.from(groups.values()).sort(
    (a, b) => new Date(b.primary.timestamp).getTime() - new Date(a.primary.timestamp).getTime()
  );
};

export const formatGroupTimeRange = (alerts: Alert[]) => {
  if (alerts.length <= 1) return "";
  const sorted = [...alerts].sort(
    (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
  );
  const first = new Date(sorted[0].timestamp);
  const last = new Date(sorted[sorted.length - 1].timestamp);
  const fmt = new Intl.DateTimeFormat("zh-TW", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  });
  return `${fmt.format(first)} - ${fmt.format(last)}`;
};

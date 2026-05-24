import type { Alert } from "@/lib/types";

function alertText(alert: Alert) {
  return [
    alert.rule_id,
    alert.rule_description,
    alert.summary,
    alert.business_impact,
    alert.root_cause,
    alert.technical_evidence?.module,
    ...(alert.technical_evidence?.rule?.groups || []),
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
}

export function isItFollowupAlert(alert: Alert) {
  const text = alertText(alert);
  if (["533", "534"].includes(String(alert.rule_id))) return true;
  if (alert.agent_name === "wazuh.manager") return true;
  return [
    /sca|cis|benchmark|安全設定|configuration/,
    /syscollector|system inventory|系統盤點/,
    /netstat|opened ports|listening ports|網路連接狀態|網路連接埠|port status/,
    /agent 尚未回報|未回報實際 ip|loopback/,
  ].some((pattern) => pattern.test(text));
}

export function isBossActionAlert(alert: Alert) {
  if (alert.status !== "pending") return false;
  if (isItFollowupAlert(alert)) return false;
  if (alert.severity === "critical" || alert.severity === "high") return true;
  if (alert.source_ip) return true;
  const text = alertText(alert);
  return /登入|login|brute|password|漏洞|cve|檔案|file|fim|malware|rootkit|attack|intrusion/.test(text);
}

export function bossActionAlerts(alerts: Alert[]) {
  return alerts.filter(isBossActionAlert);
}

export function itFollowupAlerts(alerts: Alert[]) {
  return alerts.filter((alert) => alert.status === "pending" && !isBossActionAlert(alert));
}

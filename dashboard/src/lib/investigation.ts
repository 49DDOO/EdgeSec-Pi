import type { Alert, InvestigationEvidence } from "@/lib/types";

export function compactIp(value?: string) {
  const ip = String(value || "").trim();
  if (!ip) return "-";
  if (/^(?:0{1,4}:){7}0*1$/i.test(ip)) return "::1";
  if (/^(?:0{1,4}:){7}0*0$/i.test(ip)) return "::";
  return ip.replace(/\b0{1,3}([0-9a-f]{1,3})\b/gi, "$1");
}

export function isLoopbackIp(value?: string) {
  const ip = compactIp(value);
  return ip === "127.0.0.1" || ip === "::1" || ip === "localhost";
}

export function firstIpLike(alert: Alert) {
  return alert.source_ip || "";
}

export function relatedIp(alert: Alert) {
  const ip = firstIpLike(alert);
  return ip && !isLoopbackIp(ip) ? compactIp(ip) : "";
}

export function investigationQuestions(alert: Alert, mode: "owner" | "analyst" = "owner") {
  const sourceIp = firstIpLike(alert);
  if (mode === "analyst") {
    return [
      sourceIp && !isLoopbackIp(sourceIp) ? `查來源 ${sourceIp} 最近 7 天相關事件。` : "",
      `查 ${alert.agent_name} 最近 24 小時異常。`,
      alert.rule_id ? `查 Rule ${alert.rule_id} 最近 7 天是否重複發生。` : "",
      "判斷是否需要立刻交給 IT。",
      "產生 IT 調查摘要。",
    ].filter(Boolean);
  }
  return [
    "這件事要立刻找 IT 處理嗎？",
    sourceIp ? `來源 ${sourceIp} 最近 7 天是否攻擊其他端點？` : "",
    `${alert.agent_name} 最近 24 小時還有其他異常嗎？`,
    "產生一份給 IT 的調查摘要。",
  ].filter(Boolean);
}

export function toolLabel(tool: string) {
  return {
    get_wazuh_alerts: "讀取事件",
    search_security_events: "搜尋事件",
    get_wazuh_agents: "查端點",
    get_wazuh_running_agents: "查在線端點",
    check_agent_health: "查端點健康",
    get_agent_processes: "查程序",
    get_agent_ports: "查網路埠",
    get_wazuh_rule_details: "查規則原文",
    get_wazuh_cluster_health: "查 Wazuh 健康",
  }[tool] || tool;
}

export function evidenceSummary(item: InvestigationEvidence) {
  if (item.tool === "search_security_events") return "Wazuh 歷史事件";
  if (item.tool === "get_wazuh_alerts") return "Wazuh 事件清單";
  if (item.tool === "get_wazuh_running_agents") return "在線端點";
  if (item.tool === "get_wazuh_agents") return "端點清單";
  if (item.tool === "check_agent_health") return "端點健康狀態";
  if (item.tool === "get_agent_processes") return "執行中程序";
  if (item.tool === "get_agent_ports") return "開放網路埠";
  if (item.tool === "get_wazuh_rule_details") return "Wazuh 規則原文";
  if (item.tool === "get_wazuh_cluster_health") return "Wazuh 平台狀態";
  return "Wazuh 查詢結果";
}

export function evidenceSentence(item: InvestigationEvidence) {
  return `已查 ${evidenceSummary(item)}`;
}

export function toolSummary(item: InvestigationEvidence) {
  const args = item.args || {};
  if (item.tool === "search_security_events") {
    const srcip = typeof args.srcip === "string" ? args.srcip : "";
    const range = typeof args.time_range === "string" ? args.time_range : "指定時間";
    return srcip ? `已查來源 IP ${srcip} 在 ${range} 內的相關事件。` : `已搜尋 ${range} 內的安全事件。`;
  }
  if (item.tool === "get_wazuh_alerts") return "已讀取 Wazuh 事件清單。";
  if (item.tool === "get_wazuh_running_agents") return "已確認目前在線的受監控端點。";
  if (item.tool === "get_wazuh_agents") return "已查詢受監控端點清單或指定端點資料。";
  if (item.tool === "check_agent_health") return "已確認指定端點是否在線與健康。";
  if (item.tool === "get_agent_processes") return "已查詢指定端點上的執行中程序。";
  if (item.tool === "get_agent_ports") return "已查詢指定端點目前開放的網路埠。";
  if (item.tool === "get_wazuh_rule_details") return "已查詢 Wazuh Manager 目前載入的規則內容。";
  if (item.tool === "get_wazuh_cluster_health") return "已檢查 Wazuh 平台健康狀態。";
  return "已查詢一項 Wazuh 資料。";
}

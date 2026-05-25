"use client";

import { useState } from "react";
import {
  AlertTriangle,
  ShieldAlert,
  CheckCircle2,
  XCircle,
  Wrench,
  Search,
  Loader2,
  ExternalLink,
} from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button, buttonVariants } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { isBossActionAlert, itFollowupAlerts } from "@/lib/alert-routing";
import { sendInvestigationMessage } from "@/lib/api";
import type { Alert, AlertStatus, InvestigationEvidence } from "@/lib/types";
import { useInvestigationSessions } from "@/lib/use-investigation-sessions";
import { cn } from "@/lib/utils";
import { toast } from "sonner";

interface ActionableAlertsProps {
  alerts: Alert[];
  onStatusChange?: (alertId: string, newStatus: AlertStatus) => void;
}

interface AlertGroup {
  key: string;
  primary: Alert;
  alerts: Alert[];
}

// 將技術術語轉換成白話文
const getPlainLanguageTitle = (alert: Alert) => {
  if (alert.summary) {
    return alert.summary;
  }
  const map: Record<string, string> = {
    "SSH 暴力破解嘗試": "有人嘗試入侵公司電腦",
    "可疑檔案變更偵測": "重要檔案被修改了",
    "異常網路流量": "網路有異常傳輸",
    "防火牆規則變更": "防火牆設定被改動",
    "軟體漏洞偵測": "軟體有安全漏洞",
    "使用者權限提升": "員工權限被提升",
  };
  return map[alert.rule_description] || alert.rule_description;
};

// 業務影響的白話版
const getPlainBusinessImpact = (alert: Alert) => {
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

const splitActionLines = (text?: string) => {
  return String(text || "")
    .split(/\n+/)
    .map((line) => line.replace(/^\s*\d+[.)、]\s*/, "").trim())
    .filter(Boolean);
};

const firstIpLike = (alert: Alert) => {
  if (alert.source_ip) return alert.source_ip;
  const text = [alert.summary, alert.rule_description, alert.root_cause, ...(alert.iocs || [])].join(" ");
  return text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/)?.[0] || "";
};

const isDocumentationIp = (value?: string) => {
  return /^(192\.0\.2|198\.51\.100|203\.0\.113)\.\d{1,3}$/.test(value || "");
};

const getDecisionQuestion = (alert: Alert) => {
  const text = `${alert.rule_description} ${alert.summary} ${alert.root_cause}`;
  const sourceIp = firstIpLike(alert);
  const source = sourceIp ? `來源 ${sourceIp}` : "這次行為";
  if (/網路連接|連線|連接|port|listening|netstat|opened ports|network/i.test(text)) {
    return "請確認這台電腦是否正在安裝、測試或啟動新服務。";
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

const groupPendingAlerts = (alerts: Alert[]): AlertGroup[] => {
  const groups = new Map<string, AlertGroup>();
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

const formatGroupTimeRange = (alerts: Alert[]) => {
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

const investigationQuestions = (alert: Alert) => {
  const sourceIp = firstIpLike(alert);
  return [
    "這件事要立刻找 IT 處理嗎？",
    sourceIp ? `來源 ${sourceIp} 最近 7 天是否攻擊其他電腦？` : "",
    `${alert.agent_name} 最近 24 小時還有其他異常嗎？`,
    "產生一份給 IT 的調查摘要。",
  ].filter(Boolean);
};

const buildInvestigationPrompt = (alert: Alert, question: string) => {
  const endpoint = alert.technical_evidence?.endpoint;
  const indicators = alert.technical_evidence?.indicators;
  const lines = [
    `問題：${question}`,
    "",
    "請針對這筆 Wazuh 事件調查：",
    alert.summary ? `事件摘要：${alert.summary}` : "",
    alert.agent_id ? `Agent ID：${alert.agent_id}` : endpoint?.agent_id ? `Agent ID：${endpoint.agent_id}` : "",
    `電腦名稱：${alert.agent_name}`,
    alert.agent_ip ? `電腦 IP：${alert.agent_ip}` : endpoint?.ip ? `電腦 IP：${endpoint.ip}` : "",
    firstIpLike(alert) ? `來源 IP：${firstIpLike(alert)}` : "",
    indicators?.username ? `帳號：${indicators.username}` : "",
    alert.rule_id ? `Rule ID：${alert.rule_id}` : "",
    alert.rule_level != null ? `Rule level：${alert.rule_level}` : "",
    alert.timestamp ? `發生時間：${alert.timestamp}` : "",
    "",
    "回答請用繁體中文，第一句先給管理者結論：是否需要立刻請 IT 處理。",
    "你只能調查與建議，不要說你已經封鎖、隔離或修改任何設備。",
  ].filter(Boolean);
  return lines.join("\n");
};

const evidenceSummary = (item: InvestigationEvidence) => {
  if (item.tool === "search_security_events") return "已查 Wazuh 歷史事件";
  if (item.tool === "get_wazuh_alerts") return "已讀取告警清單";
  if (item.tool === "get_wazuh_running_agents") return "已確認在線電腦";
  if (item.tool === "get_wazuh_agents") return "已查詢電腦清單";
  if (item.tool === "check_agent_health") return "已確認電腦健康狀態";
  if (item.tool === "get_agent_processes") return "已查詢執行中程序";
  if (item.tool === "get_agent_ports") return "已查詢開放網路埠";
  if (item.tool === "get_wazuh_cluster_health") return "已檢查 Wazuh 平台狀態";
  return "已查詢 Wazuh 資料";
};

export function ActionableAlerts({ alerts, onStatusChange }: ActionableAlertsProps) {
  const bossAlerts = alerts.filter(isBossActionAlert);
  const itAlerts = itFollowupAlerts(alerts);
  const alertGroups = groupPendingAlerts(bossAlerts);
  const [investigatingGroup, setInvestigatingGroup] = useState<AlertGroup | null>(null);
  const [investigationLoading, setInvestigationLoading] = useState(false);
  const { getSession, saveSession } = useInvestigationSessions();
  
  const handleAction = (group: AlertGroup, action: "it" | "ok" | "false") => {
    const statusMap: Record<string, AlertStatus> = {
      it: "acknowledged",
      ok: "resolved",
      false: "false_positive",
    };
    const labelMap: Record<string, string> = {
      it: "已轉交 IT 處理",
      ok: "已標記為正常",
      false: "已標記為誤報",
    };
    group.alerts.forEach((alert) => onStatusChange?.(alert.id, statusMap[action]));
    toast.success(labelMap[action], {
      description: group.alerts.length > 1 ? `已套用到 ${group.alerts.length} 筆同類告警` : undefined,
    });
  };

  const openInvestigation = (group: AlertGroup) => {
    setInvestigatingGroup(group);
  };

  const runInvestigation = async (question: string) => {
    if (!investigatingGroup || investigationLoading) return;
    const alert = investigatingGroup.primary;
    const sessionKey = `today:${investigatingGroup.key}`;
    const currentSession = getSession(sessionKey);
    const prompt = buildInvestigationPrompt(alert, question);
    const nextMessages = [
      ...currentSession.messages,
      { role: "user" as const, content: question },
    ];
    saveSession(sessionKey, { messages: nextMessages, evidence: [] });
    setInvestigationLoading(true);
    try {
      const response = await sendInvestigationMessage([
        ...currentSession.messages,
        { role: "user", content: prompt },
      ]);
      saveSession(sessionKey, {
        messages: [
          ...nextMessages,
          { role: "assistant", content: response.answer_zh },
        ],
        evidence: response.evidence || [],
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      saveSession(sessionKey, {
        messages: [
          ...nextMessages,
          { role: "assistant", content: `調查失敗：${message}` },
        ],
        evidence: [],
      });
      toast.error("調查失敗", { description: message });
    } finally {
      setInvestigationLoading(false);
    }
  };

  if (alertGroups.length === 0) {
    return (
      <Card>
        <CardContent className="flex flex-col items-center justify-center py-12 text-center">
          <CheckCircle2 className="mb-4 size-16 text-success" />
          <h3 className="text-xl font-semibold">沒有待處理事項</h3>
          <p className="mt-2 text-muted-foreground">
            目前沒有需要老闆決定的資安事件
          </p>
          {itAlerts.length > 0 && (
            <p className="mt-3 rounded-lg bg-muted px-3 py-2 text-sm text-muted-foreground">
              IT 仍有 {itAlerts.length} 件技術項目待確認，已放在告警紀錄裡。
            </p>
          )}
        </CardContent>
      </Card>
    );
  }

  const investigatingAlert = investigatingGroup?.primary;
  const investigatingCount = investigatingGroup?.alerts.length || 0;
  const investigationSessionKey = investigatingGroup ? `today:${investigatingGroup.key}` : "";
  const investigationSession = getSession(investigationSessionKey);

  return (
    <>
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <AlertTriangle className="size-5 text-high" />
          今日需要決定
        </CardTitle>
        <CardDescription>
          只列需要老闆判斷的事件；技術噪音已移到告警紀錄
          {alertGroups.some((group) => group.alerts.length > 1)
            ? "。同一台電腦的同類告警已合併顯示"
            : ""}
          {itAlerts.length > 0 ? `。另有 ${itAlerts.length} 件 IT 待確認項目` : ""}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {alertGroups.map((group, index) => {
          const alert = group.primary;
          const groupedCount = group.alerts.length;
          const sourceIp = firstIpLike(alert);
          const isTestLike = Boolean(alert.sampledata || isDocumentationIp(sourceIp));
          return (
          <div key={group.key}>
            {index > 0 && <Separator className="my-4" />}
            <div className="space-y-3">
              {/* 標題和嚴重程度 */}
              <div className="flex flex-wrap items-start justify-between gap-2">
                <div className="flex items-center gap-2">
                  {alert.severity === "critical" ? (
                    <ShieldAlert className="size-5 text-critical" />
                  ) : (
                    <AlertTriangle className="size-5 text-high" />
                  )}
                  <span className="font-semibold">{getPlainLanguageTitle(alert)}</span>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  {groupedCount > 1 && (
                    <Badge variant="outline">同類 {groupedCount} 筆</Badge>
                  )}
                  {isTestLike && (
                    <Badge variant="outline" className="border-blue-300 bg-blue-50 text-blue-700 dark:border-blue-900 dark:bg-blue-950/30 dark:text-blue-200">
                      {alert.sampledata ? "測試資料" : "測試/文件 IP"}
                    </Badge>
                  )}
                  <Badge
                    variant={alert.severity === "critical" ? "destructive" : "secondary"}
                  >
                    {alert.severity === "critical" ? "緊急" : "重要"}
                  </Badge>
                </div>
              </div>

              {/* 一句話說明影響 */}
              <div className="rounded-lg bg-muted/50 p-3">
                <p className="text-sm">
                  <span className="font-medium">影響：</span>
                  {getPlainBusinessImpact(alert)}
                </p>
                <p className="mt-2 text-sm">
                  <span className="font-medium">現在要確認：</span>
                  {getDecisionQuestion(alert)}
                </p>
                <p className="mt-2 text-xs text-muted-foreground">
                  電腦：{alert.agent_name}
                  {alert.purpose ? ` / 用途：${alert.purpose}` : ""}
                  {sourceIp ? ` / 來源 IP：${sourceIp}` : ""}
                </p>
                {isDocumentationIp(sourceIp) && (
                  <p className="mt-1 text-xs text-blue-700 dark:text-blue-200">
                    此來源 IP 屬於文件保留網段，通常代表測試或範例資料，不是真實外部攻擊來源。
                  </p>
                )}
                {groupedCount > 1 && (
                  <p className="mt-1 text-xs text-muted-foreground">
                    發生次數：{groupedCount} 次 / 時間：{formatGroupTimeRange(group.alerts)}
                  </p>
                )}
              </div>

              {splitActionLines(alert.recommended_action).length > 0 && (
                <div className="border-l-2 border-border pl-3">
                  <div className="text-xs font-medium text-muted-foreground">建議處理順序</div>
                  <ol className="mt-2 list-decimal space-y-1 pl-5 text-sm">
                    {splitActionLines(alert.recommended_action).slice(0, 4).map((line) => (
                      <li key={line}>{line}</li>
                    ))}
                  </ol>
                </div>
              )}

              {/* 簡化的動作按鈕 */}
              <div className="flex flex-wrap gap-2">
                <Button
                  type="button"
                  variant="secondary"
                  size="sm"
                  onClick={() => openInvestigation(group)}
                  className="gap-1"
                >
                  <Search data-icon="inline-start" />
                  用 MCP 查證
                </Button>
                <Button
                  size="sm"
                  onClick={() => handleAction(group, "it")}
                  className="gap-1"
                >
                  <Wrench data-icon="inline-start" />
                  交給 IT 處理
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => handleAction(group, "ok")}
                  className="gap-1"
                >
                  <CheckCircle2 data-icon="inline-start" />
                  確認為正常
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => handleAction(group, "false")}
                  className="gap-1 text-muted-foreground"
                >
                  <XCircle data-icon="inline-start" />
                  標記誤報
                </Button>
                <a
                  href={`/?tab=alerts&alert=${encodeURIComponent(alert.id)}`}
                  className={cn(
                    buttonVariants({ variant: "link", size: "sm" }),
                    "gap-1 px-1 text-muted-foreground"
                  )}
                >
                  <ExternalLink data-icon="inline-start" />
                  查看完整告警
                </a>
              </div>
              {groupedCount > 1 && (
                <div className="text-xs text-muted-foreground">
                  這張卡合併了 {groupedCount} 筆同類告警。按處理按鈕時，會一起更新這些告警的狀態。
                </div>
              )}
            </div>
          </div>
          );
        })}
      </CardContent>
    </Card>
    <Sheet
      open={Boolean(investigatingGroup)}
      onOpenChange={(open) => {
        if (!open) setInvestigatingGroup(null);
      }}
    >
      <SheetContent className="w-[min(720px,calc(100vw-1rem))] gap-0 p-0 sm:max-w-none">
        <SheetHeader className="border-b pr-12">
          <SheetTitle>MCP 查證</SheetTitle>
          <SheetDescription>
            告警已先由 LLM 翻成白話；需要更多線索時，才從這裡讀取 Wazuh 紀錄。
          </SheetDescription>
        </SheetHeader>

        {investigatingAlert && (
          <div className="flex min-h-0 flex-1 flex-col">
            <div className="space-y-4 overflow-auto p-4">
              <div className="rounded-lg border bg-muted/40 p-4">
                <div className="text-xs font-medium text-muted-foreground">LLM 白話摘要</div>
                <div className="mt-1 text-base font-semibold">
                  {getPlainLanguageTitle(investigatingAlert)}
                </div>
                <div className="mt-2 text-sm leading-6 text-muted-foreground">
                  {getPlainBusinessImpact(investigatingAlert)}
                </div>
                <div className="mt-3 grid gap-3 text-sm sm:grid-cols-2">
                  <div>
                    <div className="text-xs text-muted-foreground">電腦</div>
                    <div>{investigatingAlert.agent_name}</div>
                  </div>
                  <div>
                    <div className="text-xs text-muted-foreground">來源 IP</div>
                    <div>{firstIpLike(investigatingAlert) || "-"}</div>
                  </div>
                  <div>
                    <div className="text-xs text-muted-foreground">Rule</div>
                    <div>
                      {investigatingAlert.rule_id}
                      {investigatingAlert.rule_level != null ? ` / level ${investigatingAlert.rule_level}` : ""}
                    </div>
                  </div>
                  <div>
                    <div className="text-xs text-muted-foreground">狀態</div>
                    <div>{investigatingCount > 1 ? `同類 ${investigatingCount} 筆待確認` : "待確認"}</div>
                  </div>
                </div>
              </div>

              <div className="rounded-lg border border-amber-200 bg-amber-50 p-3 text-sm leading-6 text-amber-950 dark:border-amber-900/50 dark:bg-amber-950/20 dark:text-amber-100">
                MCP 是按需查證工具。點下方問題後才會讀取 Wazuh 紀錄；這裡不會封鎖、隔離、停用帳號或修改設定。
              </div>

              <div className="space-y-2">
                <div className="text-sm font-medium">先問這幾個問題</div>
                <div className="flex flex-wrap gap-2">
                  {investigationQuestions(investigatingAlert).map((question) => (
                    <Button
                      key={question}
                      type="button"
                      variant="outline"
                      size="sm"
                      disabled={investigationLoading}
                      onClick={() => void runInvestigation(question)}
                    >
                      {question}
                    </Button>
                  ))}
                </div>
              </div>

              <div className="space-y-3">
                {investigationSession.messages.length === 0 ? (
                  <div className="rounded-lg border border-dashed p-4 text-sm text-muted-foreground">
                    尚未啟動 MCP 查證。上方白話摘要已可先判斷；需要更多線索時再點問題查 Wazuh。
                  </div>
                ) : (
                  investigationSession.messages.map((message, index) => (
                    <div
                      key={`${message.role}-${index}`}
                      className={`rounded-lg border p-3 text-sm leading-6 ${
                        message.role === "user" ? "bg-muted/50" : "bg-background"
                      }`}
                    >
                      <div className="mb-1 text-xs font-medium text-muted-foreground">
                        {message.role === "user" ? "調查問題" : "調查結果"}
                      </div>
                      <div className="whitespace-pre-line">{message.content}</div>
                    </div>
                  ))
                )}
                {investigationLoading && (
                  <div className="flex items-center gap-2 rounded-lg border p-3 text-sm text-muted-foreground">
                    <Loader2 className="size-4 animate-spin" />
                    正在查 Wazuh 紀錄
                  </div>
                )}
              </div>

              {investigationSession.evidence.length > 0 && (
                <details className="rounded-lg border p-3">
                  <summary className="cursor-pointer text-sm font-medium">MCP 查詢紀錄</summary>
                  <div className="mt-3 space-y-2">
                    {investigationSession.evidence.map((item, index) => (
                      <div key={`${item.tool}-${index}`} className="rounded-md border bg-muted/30 p-3 text-xs">
                        <div className="font-medium">{evidenceSummary(item)}</div>
                        <pre className="mt-2 max-h-28 overflow-auto whitespace-pre-wrap text-muted-foreground">
                          {JSON.stringify(item.args || {}, null, 2)}
                          {"\n\n"}
                          {item.result_preview || ""}
                        </pre>
                      </div>
                    ))}
                  </div>
                </details>
              )}
            </div>

            <SheetFooter className="border-t bg-card sm:flex-row sm:justify-between">
              <div className="flex flex-wrap gap-2">
                <Button
                  onClick={() => {
                    handleAction(investigatingGroup, "it");
                    setInvestigatingGroup(null);
                  }}
                  className="gap-1"
                >
                  <Wrench data-icon="inline-start" />
                  交給 IT 處理
                </Button>
                <Button
                  variant="outline"
                  onClick={() => {
                    handleAction(investigatingGroup, "ok");
                    setInvestigatingGroup(null);
                  }}
                >
                  <CheckCircle2 data-icon="inline-start" />
                  確認正常
                </Button>
                <Button
                  variant="outline"
                  onClick={() => {
                    handleAction(investigatingGroup, "false");
                    setInvestigatingGroup(null);
                  }}
                >
                  <XCircle data-icon="inline-start" />
                  標記誤報
                </Button>
              </div>
              <Button variant="ghost" onClick={() => setInvestigatingGroup(null)}>
                回到待辦
              </Button>
            </SheetFooter>
          </div>
        )}
      </SheetContent>
    </Sheet>
    </>
  );
}

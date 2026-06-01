"use client";

import { FormEvent, useMemo, useState } from "react";
import Link from "next/link";
import {
  Activity,
  ArrowLeft,
  Bell,
  Bot,
  BrainCircuit,
  CheckCircle2,
  Circle,
  Database,
  ExternalLink,
  Loader2,
  MessageSquareText,
  MoreHorizontal,
  Send,
  ShieldAlert,
} from "lucide-react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button, buttonVariants } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Textarea } from "@/components/ui/textarea";
import { isBossActionAlert } from "@/lib/alert-routing";
import { sendAlertInvestigationMessage, type DashboardSummary } from "@/lib/api";
import { severityLabels } from "@/lib/labels";
import { normalizedSourceKey, sourceLabel } from "@/lib/source-labels";
import type { Alert, AlertStatus, InvestigationMessage } from "@/lib/types";
import { useInvestigationSessions } from "@/lib/use-investigation-sessions";
import { cn } from "@/lib/utils";

interface AgentRunsDashboardProps {
  summary: DashboardSummary;
  visibleAlerts: Alert[];
  onStatusChange: (alertId: string, newStatus: AlertStatus) => void;
}

interface AgentRunGroup {
  key: string;
  primary: Alert;
  alerts: Alert[];
}

const severityRank: Record<Alert["severity"], number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

function healthText(status: "healthy" | "degraded" | "down") {
  if (status === "healthy") return "Ready";
  if (status === "degraded") return "Attention";
  return "Down";
}

function healthClass(status: "healthy" | "degraded" | "down") {
  if (status === "healthy") return "text-success";
  if (status === "degraded") return "text-medium";
  return "text-destructive";
}

function severityClass(severity: Alert["severity"]) {
  if (severity === "critical") return "border-critical/30 bg-critical/10 text-critical";
  if (severity === "high") return "border-high/30 bg-high/10 text-high";
  if (severity === "medium") return "border-medium/40 bg-medium/10 text-medium";
  return "border-border bg-muted/40 text-muted-foreground";
}

function statusClass(status: AlertStatus) {
  if (status === "pending") return "border-high/30 bg-high/10 text-high";
  if (status === "acknowledged") return "border-medium/40 bg-medium/10 text-medium";
  if (status === "resolved") return "border-success/30 bg-success/10 text-success";
  return "border-border bg-muted/40 text-muted-foreground";
}

function relativeTime(value: string) {
  const time = new Date(value).getTime();
  if (Number.isNaN(time)) return "";
  const diffMinutes = Math.max(0, Math.round((Date.now() - time) / 60000));
  if (diffMinutes < 1) return "剛剛";
  if (diffMinutes < 60) return `${diffMinutes} 分鐘前`;
  const diffHours = Math.round(diffMinutes / 60);
  if (diffHours < 24) return `${diffHours} 小時前`;
  return `${Math.round(diffHours / 24)} 天前`;
}

function primaryAction(alert: Alert) {
  if (alert.status === "pending" && isBossActionAlert(alert)) return "需要你判斷";
  if (alert.status === "pending") return "先確認";
  if (alert.status === "acknowledged") return "追蹤中";
  if (alert.status === "false_positive") return "誤報";
  return "已歸檔";
}

function bossNextStep(alert: Alert) {
  const text = [
    alert.summary,
    alert.rule_description,
    alert.recommended_action,
    alert.root_cause,
  ].join(" ");
  if (/rootkit|惡意|malware|木馬|隱藏|信用卡|敏感/i.test(text)) {
    return "不認得就先讓這台電腦離線，避免繼續外連或碰敏感資料。";
  }
  if (/ssh|login|登入|brute|password|密碼/i.test(text)) {
    return "如果不是你或同事操作，先不要放行，改密碼並保留紀錄。";
  }
  if (/port|連接埠|網路連接|netstat|opened ports|connection/i.test(text)) {
    return "確認是否剛安裝軟體、開發工具或遠端連線；不認得就先關掉該程式。";
  }
  if (/file|檔案|fim|modified|changed/i.test(text)) {
    return "確認是否有人核准這次檔案或設定變更；不認得就先不要覆蓋紀錄。";
  }
  if (/CVE|漏洞|vulnerab|patch|更新/i.test(text)) {
    return "安排更新或暫停對外服務；不確定時先降低暴露風險。";
  }
  return "認得就歸檔；不認得就先保守處理並保留紀錄。";
}

function unrecognizedEffect(alert: Alert) {
  const text = [
    alert.summary,
    alert.rule_description,
    alert.recommended_action,
    alert.root_cause,
  ].join(" ");
  if (/rootkit|惡意|malware|木馬|隱藏|信用卡|敏感/i.test(text)) {
    return "按下後：這組事件會保留在追蹤中；不會自動隔離電腦，下一步會建議先手動離線。";
  }
  if (/ssh|login|登入|brute|password|密碼/i.test(text)) {
    return "按下後：這組事件會保留在追蹤中；不會自動封鎖或改密碼，下一步會提醒你先改密碼與確認登入。";
  }
  if (/port|連接埠|網路連接|netstat|opened ports|connection/i.test(text)) {
    return "按下後：這組事件會保留在追蹤中；不會自動關程式，下一步會提醒你確認或關閉不認得的程式。";
  }
  return "按下後：這組事件會保留在追蹤中；不會自動做危險處置。";
}

function recognizedEffect() {
  return "按下後：這組事件會標成已歸檔，首頁不再提醒。";
}

function falsePositiveEffect() {
  return "按下後：這組事件會標成誤報，短時間內同類提醒會降低。";
}

function runStateClass(alert: Alert) {
  if (alert.status === "pending" && isBossActionAlert(alert)) {
    return "border-high/30 bg-high/10 text-high";
  }
  if (alert.status === "pending") return "border-medium/40 bg-medium/10 text-medium";
  return statusClass(alert.status);
}

function runGroupKey(alert: Alert) {
  const family = alert.rule_id || alert.technical_evidence?.module || alert.rule_description || alert.summary;
  return [
    normalizedSourceKey(alert.siem_source),
    alert.agent_id || alert.agent_name,
    family,
  ].join("|").toLowerCase();
}

function groupAgentRuns(alerts: Alert[]): AgentRunGroup[] {
  const groups = new Map<string, AgentRunGroup>();
  alerts.forEach((alert) => {
    const key = runGroupKey(alert);
    const current = groups.get(key);
    if (!current) {
      groups.set(key, { key, primary: alert, alerts: [alert] });
      return;
    }
    current.alerts.push(alert);
    const currentPending = current.primary.status === "pending" ? 1 : 0;
    const nextPending = alert.status === "pending" ? 1 : 0;
    const shouldReplace =
      nextPending > currentPending
      || (
        nextPending === currentPending
        && severityRank[alert.severity] > severityRank[current.primary.severity]
      )
      || (
        nextPending === currentPending
        && severityRank[alert.severity] === severityRank[current.primary.severity]
        && new Date(alert.timestamp).getTime() > new Date(current.primary.timestamp).getTime()
      );
    if (shouldReplace) current.primary = alert;
  });
  return Array.from(groups.values()).sort((a, b) => {
    const aPending = a.alerts.some((alert) => alert.status === "pending") ? 1 : 0;
    const bPending = b.alerts.some((alert) => alert.status === "pending") ? 1 : 0;
    if (aPending !== bPending) return bPending - aPending;
    const severityDiff = severityRank[b.primary.severity] - severityRank[a.primary.severity];
    if (severityDiff !== 0) return severityDiff;
    return new Date(b.primary.timestamp).getTime() - new Date(a.primary.timestamp).getTime();
  });
}

function assetKey(alert: Alert) {
  return alert.agent_id || alert.agent_name || alert.agent_ip || alert.id;
}

function chatGreeting(group: AgentRunGroup | undefined): InvestigationMessage {
  const alert = group?.primary;
  if (!alert) {
    return {
      role: "assistant",
      content: "請先點左邊一台電腦或一組事件，我會針對那台電腦回答。",
    };
  }
  return {
    role: "assistant",
    content: [
      `我正在看 ${alert.purpose || alert.agent_name || "這台電腦"}。`,
      group.alerts.length > 1 ? `目前同類訊號共 ${group.alerts.length} 筆。` : "",
      "你可以直接問：這台電腦現在危險嗎？我該先做哪一步？",
    ].filter(Boolean).join("\n"),
  };
}

function isStoredChatGreeting(message: InvestigationMessage) {
  return message.role === "assistant" && message.content.startsWith("我正在看 ");
}

function splitLongSentence(text: string) {
  if (text.length <= 160) return [text];
  const parts = text
    .split(/(?<=[。！？])\s*/)
    .map((part) => part.trim())
    .filter(Boolean);
  if (parts.length <= 1) return [text];
  const blocks: string[] = [];
  let current = "";
  parts.forEach((part) => {
    const next = current ? `${current}${part}` : part;
    if (next.length > 180 && current) {
      blocks.push(current);
      current = part;
    } else {
      current = next;
    }
  });
  if (current) blocks.push(current);
  return blocks;
}

function chatContentBlocks(content: string) {
  return content
    .split(/\n+/)
    .map((line) => line.trim())
    .filter(Boolean)
    .flatMap(splitLongSentence);
}

export function AgentRunsDashboard({
  onStatusChange,
  summary,
  visibleAlerts,
}: AgentRunsDashboardProps) {
  const sourceKeys = Array.from(
    new Set(visibleAlerts.map((alert) => normalizedSourceKey(alert.siem_source)))
  );
  const sourceCount = Math.max(
    sourceKeys.length,
    summary.systemHealth.wazuh_connection === "connected" ? 1 : 0
  );
  const pendingDecisionCount = visibleAlerts.filter((alert) => (
    alert.status === "pending" && isBossActionAlert(alert)
  )).length;
  const pendingRunCount = visibleAlerts.filter((alert) => alert.status === "pending").length;
  const runs = groupAgentRuns(visibleAlerts)
    .slice(0, 12);
  const [selectedKey, setSelectedKey] = useState("");
  const [chatOpen, setChatOpen] = useState(false);
  const [chatInput, setChatInput] = useState("");
  const [chatLoading, setChatLoading] = useState(false);
  const { getSession, saveSession } = useInvestigationSessions();
  const selectedGroup = useMemo(
    () => runs.find((group) => group.key === selectedKey) || runs[0],
    [runs, selectedKey]
  );
  const selectedAlert = selectedGroup?.primary;
  const chatKey = selectedAlert ? `asset:${assetKey(selectedAlert)}` : "";
  const chatSession = getSession(chatKey);
  const storedChatMessages = chatSession.messages.filter((message, index) => (
    index !== 0 || !isStoredChatGreeting(message)
  ));
  const chatMessages = [
    chatGreeting(selectedGroup),
    ...storedChatMessages,
  ];
  const quickQuestions = selectedAlert
    ? [
        "這台電腦現在危險嗎？",
        "我不懂，請直接告訴我第一步要做什麼。",
        `${selectedAlert.agent_name} 最近還有其他異常嗎？`,
      ]
    : [];
  const statusItems = [
    {
      label: "Agent",
      value: "Running",
      icon: Activity,
      className: "text-success",
    },
    {
      label: "Sources",
      value: `${sourceCount}`,
      icon: Database,
      href: "/settings/sources",
      className: sourceCount > 0 ? "text-success" : "text-medium",
    },
    {
      label: "AI",
      value: healthText(summary.systemHealth.llm_service),
      icon: BrainCircuit,
      href: "/settings/ai-model",
      className: healthClass(summary.systemHealth.llm_service),
    },
    {
      label: "Notify",
      value: healthText(summary.systemHealth.notification_service),
      icon: Bell,
      href: "/settings/notifications",
      className: healthClass(summary.systemHealth.notification_service),
    },
    {
      label: "Queue",
      value: String(summary.systemHealth.analysis_queue),
      icon: Circle,
      href: "/settings/status",
      className: summary.systemHealth.analysis_queue > 0 ? "text-medium" : "text-success",
    },
  ];

  async function askAssetAgent(question: string) {
    const content = question.trim();
    if (!content || !selectedAlert || chatLoading) return;
    const previousMessages = [
      chatGreeting(selectedGroup),
      ...storedChatMessages,
    ];
    const nextMessages = [...storedChatMessages, { role: "user" as const, content }];
    saveSession(chatKey, { messages: nextMessages, evidence: chatSession.evidence });
    setChatInput("");
    setChatLoading(true);
    try {
      const response = await sendAlertInvestigationMessage({
        alertId: selectedAlert.id,
        question: content,
        messages: previousMessages,
      });
      saveSession(chatKey, {
        messages: [
          ...storedChatMessages,
          { role: "user", content },
          { role: "assistant", content: response.answer_zh },
        ],
        evidence: response.evidence || [],
        suggestions: response.suggestions || [],
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      saveSession(chatKey, {
        messages: [
          ...storedChatMessages,
          { role: "user", content },
          { role: "assistant", content: `我查詢失敗：${message}` },
        ],
        evidence: chatSession.evidence,
      });
      toast.error("Agent Chat 查詢失敗", { description: message });
    } finally {
      setChatLoading(false);
    }
  }

  function onChatSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void askAssetAgent(chatInput);
  }

  const selectedPendingAlerts = selectedGroup?.alerts.filter((item) => item.status === "pending") || [];
  const selectedStatusTargets = selectedPendingAlerts.length > 0
    ? selectedPendingAlerts
    : selectedGroup?.alerts || [];
  const applySelectedStatus = (status: AlertStatus) => {
    selectedStatusTargets.forEach((item) => onStatusChange(item.id, status));
  };

  return (
    <div className="space-y-4">
      {!chatOpen && (
        <div className="flex flex-wrap gap-2 border-b border-border pb-4">
          {statusItems.map((item) => {
            const Icon = item.icon;
            const content = (
              <span className="inline-flex h-8 items-center gap-2 rounded-md border bg-card px-2.5 text-sm">
                <Icon className={cn("size-3.5", item.className)} />
                <span className="text-muted-foreground">{item.label}</span>
                <span className="font-medium">{item.value}</span>
              </span>
            );
            return item.href ? (
              <Link key={item.label} href={item.href} className="transition hover:opacity-80">
                {content}
              </Link>
            ) : (
              <span key={item.label}>{content}</span>
            );
          })}
        </div>
      )}

      {chatOpen && selectedGroup && selectedAlert ? (
        <div className="grid h-[calc(100vh-9.5rem)] min-h-[640px] gap-4 xl:grid-cols-[minmax(0,1fr)_320px]">
          <Card className="overflow-hidden">
            <CardContent className="flex h-full min-h-0 flex-col p-0">
              <div className="border-b px-5 py-4">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <div className="flex items-center gap-2">
                      <MessageSquareText className="size-4 text-primary" />
                      <div className="text-base font-semibold">
                        {selectedAlert.agent_name} 的 Agent Chat
                      </div>
                    </div>
                    <p className="mt-1 text-xs text-muted-foreground">
                      只查詢與說明，不會自動封鎖、隔離或修改設定。
                    </p>
                  </div>
                  <Button
                    variant="ghost"
                    size="sm"
                    aria-label="關閉 Agent Chat"
                    title="關閉 Agent Chat"
                    onClick={() => setChatOpen(false)}
                  >
                    <ArrowLeft className="size-4" />
                    回列表
                  </Button>
                </div>
              </div>

              <div className="flex-1 space-y-4 overflow-auto px-5 py-5">
                {chatMessages.map((message, index) => {
                  const user = message.role === "user";
                  const blocks = chatContentBlocks(message.content);
                  return (
                    <div key={`${message.role}-${index}`} className={cn("flex gap-2", user && "justify-end")}>
                      {!user && (
                        <div className="flex size-7 shrink-0 items-center justify-center rounded-md bg-primary/10">
                          <Bot className="size-3.5 text-primary" />
                        </div>
                      )}
                      <div
                        className={cn(
                          "rounded-lg px-4 py-3 text-sm leading-6",
                          user ? "bg-primary text-primary-foreground" : "border bg-muted/30"
                        )}
                        style={{ maxWidth: user ? "min(520px, 76%)" : "min(760px, 84%)" }}
                      >
                        <div className="space-y-2">
                          {blocks.map((block, blockIndex) => (
                            <p key={blockIndex} className={cn(blockIndex === 0 && !user && "font-medium")}>
                              {block}
                            </p>
                          ))}
                        </div>
                      </div>
                    </div>
                  );
                })}
                {chatLoading && (
                  <div className="flex items-center gap-2 text-sm text-muted-foreground">
                    <Loader2 className="size-4 animate-spin" />
                    Agent 正在查這台電腦...
                  </div>
                )}
              </div>

              <div className="border-t bg-card px-5 py-4">
                <div className="mb-3 flex flex-wrap gap-2">
                  {quickQuestions.map((question) => (
                    <Button
                      key={question}
                      variant="outline"
                      size="sm"
                      onClick={() => void askAssetAgent(question)}
                      disabled={chatLoading}
                    >
                      {question}
                    </Button>
                  ))}
                </div>
                <form className="flex items-end gap-2" onSubmit={onChatSubmit}>
                  <Textarea
                    value={chatInput}
                    onChange={(event) => setChatInput(event.target.value)}
                    placeholder="問這台電腦，例如：我現在要做什麼？"
                    className="min-h-11 resize-none rounded-lg"
                    onKeyDown={(event) => {
                      if (event.key === "Enter" && !event.shiftKey) {
                        event.preventDefault();
                        void askAssetAgent(chatInput);
                      }
                    }}
                  />
                  <Button type="submit" size="icon" disabled={!chatInput.trim() || chatLoading}>
                    <Send className="size-4" />
                  </Button>
                </form>
              </div>
            </CardContent>
          </Card>

          <Card className="overflow-hidden">
            <CardContent className="flex h-full min-h-0 flex-col p-0">
              <div className="border-b px-5 py-4">
                <div className="text-base font-semibold">Agent Profile</div>
                <p className="mt-1 text-xs text-muted-foreground">目前選取的受監控電腦</p>
              </div>
              <div className="flex-1 space-y-5 overflow-auto px-5 py-4">
                <div className="flex items-center gap-3">
                  <div className="flex size-10 items-center justify-center rounded-lg bg-primary/10 text-sm font-semibold text-primary">
                    {selectedAlert.agent_name.slice(0, 2).toUpperCase()}
                  </div>
                  <div className="min-w-0">
                    <div className="truncate font-semibold">{selectedAlert.agent_name}</div>
                    <div className="text-xs text-muted-foreground">{selectedAlert.purpose || "用途尚未設定"}</div>
                  </div>
                </div>

                <div className="space-y-3 rounded-lg border p-3 text-sm">
                  <div className="flex items-center justify-between gap-3">
                    <span className="text-muted-foreground">來源</span>
                    <span className="font-medium">{sourceLabel(selectedAlert.siem_source)}</span>
                  </div>
                  <div className="flex items-center justify-between gap-3">
                    <span className="text-muted-foreground">訊號數</span>
                    <span className="font-medium">{selectedGroup.alerts.length} 筆</span>
                  </div>
                  <div className="flex items-center justify-between gap-3">
                    <span className="text-muted-foreground">最新風險</span>
                    <Badge variant="outline" className={cn("border", severityClass(selectedAlert.severity))}>
                      {severityLabels[selectedAlert.severity]}
                    </Badge>
                  </div>
                </div>
                <div>
                  <div className="text-sm font-medium">Agent 建議</div>
                  <div className="mt-2 rounded-lg border bg-muted/30 p-3 text-sm leading-6">
                    {bossNextStep(selectedAlert)}
                  </div>
                </div>
              </div>
              {selectedAlert.status === "pending" ? (
                <div className="space-y-2 border-t p-5">
                  <Button
                    className="w-full"
                    title={unrecognizedEffect(selectedAlert)}
                    onClick={() => applySelectedStatus("acknowledged")}
                  >
                    不認得，先追蹤
                  </Button>
                  <Button
                    variant="outline"
                    className="w-full"
                    title={recognizedEffect()}
                    onClick={() => applySelectedStatus("resolved")}
                  >
                    認得，歸檔
                  </Button>
                  <Button
                    variant="ghost"
                    className="w-full"
                    title={falsePositiveEffect()}
                    onClick={() => applySelectedStatus("false_positive")}
                  >
                    誤報
                  </Button>
                </div>
              ) : (
                <div className="flex items-center gap-2 border-t p-5 text-sm text-muted-foreground">
                  <CheckCircle2 className="size-4 text-success" />
                  已處理
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      ) : (
        <Card>
          <CardContent className="p-0">
            <div className="flex items-center justify-between gap-3 border-b px-4 py-3">
              <div className="flex items-center gap-2">
                <ShieldAlert className={cn("size-4", pendingDecisionCount > 0 ? "text-high" : "text-success")} />
                <span className="text-sm font-medium text-foreground">
                  {runs.length} 類事件
                </span>
                <span className="text-sm text-muted-foreground">
                  {pendingDecisionCount > 0
                    ? `${pendingDecisionCount} 筆原始訊號要你判斷`
                    : `${pendingRunCount} 筆原始訊號待確認`}
                </span>
              </div>
              <Link href="/events" className={buttonVariants({ variant: "outline", size: "sm" })}>
                全部調查紀錄
                <ExternalLink data-icon="inline-end" />
              </Link>
            </div>

            {runs.length === 0 ? (
              <div className="flex h-28 items-center justify-center text-sm text-muted-foreground">
                目前沒有 Agent runs。
              </div>
            ) : (
              <div className="divide-y divide-border">
                {runs.map((group) => {
                  const alert = group.primary;
                  const pendingAlerts = group.alerts.filter((item) => item.status === "pending");
                  const affectedCount = group.alerts.length;
                  const applyStatus = (status: AlertStatus) => {
                    const targets = pendingAlerts.length > 0 ? pendingAlerts : group.alerts;
                    targets.forEach((item) => onStatusChange(item.id, status));
                  };
                  return (
                    <div
                      key={group.key}
                      className="grid gap-4 px-4 py-4 transition hover:bg-muted/30 lg:grid-cols-[minmax(0,1fr)_200px]"
                    >
                      <button
                        type="button"
                        className="min-w-0 space-y-2 text-left"
                        onClick={() => {
                          setSelectedKey(group.key);
                          setChatOpen(true);
                        }}
                      >
                        <div className="flex flex-wrap items-center gap-2">
                          <Badge variant="outline" className={cn("border", runStateClass(alert))}>
                            {primaryAction(alert)}
                          </Badge>
                          <Badge variant="outline" className={cn("border", severityClass(alert.severity))}>
                            {severityLabels[alert.severity]}
                          </Badge>
                          <span className="text-xs text-muted-foreground">
                            {sourceLabel(alert.siem_source)} · {relativeTime(alert.timestamp)}
                          </span>
                          {affectedCount > 1 && (
                            <Badge variant="outline">
                              共 {affectedCount} 筆
                            </Badge>
                          )}
                        </div>
                        <div className="text-base font-semibold leading-6 text-foreground">
                          {alert.summary || alert.rule_description}
                        </div>
                        <div className="text-sm text-muted-foreground">
                          {alert.purpose || alert.agent_name || "未命名資產"}
                        </div>
                        <div className="rounded-md border bg-muted/30 px-3 py-2 text-sm leading-6">
                          <span className="font-medium text-foreground">Agent 建議：</span>
                          <span className="text-muted-foreground">{bossNextStep(alert)}</span>
                        </div>
                      </button>

                      <div className="flex flex-col justify-center gap-2">
                        {alert.status === "pending" ? (
                          <>
                            <Button
                              className="h-10 justify-center"
                              title={unrecognizedEffect(alert)}
                              onClick={() => applyStatus("acknowledged")}
                            >
                              不認得，先追蹤
                            </Button>
                            <Button
                              variant="outline"
                              className="h-10 justify-center"
                              title={recognizedEffect()}
                              onClick={() => applyStatus("resolved")}
                            >
                              認得，歸檔
                            </Button>
                            <div className="flex gap-2">
                              <Button
                                variant="ghost"
                                size="sm"
                                title={falsePositiveEffect()}
                                className="flex-1"
                                onClick={() => applyStatus("false_positive")}
                              >
                                誤報
                              </Button>
                              <Link
                                href={`/events?alert=${encodeURIComponent(alert.id)}`}
                                className={buttonVariants({ variant: "ghost", size: "sm", className: "flex-1" })}
                              >
                                細節
                                <MoreHorizontal className="size-4" />
                              </Link>
                            </div>
                          </>
                        ) : (
                          <div className="flex items-center justify-end gap-2 text-sm text-muted-foreground">
                            <CheckCircle2 className="size-4 text-success" />
                            已處理
                            <Link
                              href={`/events?alert=${encodeURIComponent(alert.id)}`}
                              className={buttonVariants({ variant: "outline", size: "sm" })}
                            >
                              查看細節
                            </Link>
                          </div>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}

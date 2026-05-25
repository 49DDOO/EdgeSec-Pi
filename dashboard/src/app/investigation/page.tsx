"use client";

import { FormEvent, useEffect, useMemo, useRef, useState } from "react";
import {
  AlertTriangle,
  Bot,
  Loader2,
  MessageSquareText,
  Send,
  ShieldCheck,
  Wrench,
} from "lucide-react";
import { toast } from "sonner";
import { ThemeToggle } from "@/components/dashboard/theme-toggle";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Textarea } from "@/components/ui/textarea";
import { sendInvestigationMessage } from "@/lib/api";
import type {
  InvestigationEvidence,
  InvestigationMessage,
} from "@/lib/types";
import { cn } from "@/lib/utils";

const examples = [
  "查目前有哪些電腦在線或離線",
  "查最近 24 小時有哪些高風險事件",
  "查今天有沒有需要立刻請 IT 處理的事件",
  "產生一份給 IT 的查證摘要",
];

interface InvestigationContext {
  alertId?: string;
  agentId?: string;
  agentName?: string;
  agentIp?: string;
  sourceIp?: string;
  ruleId?: string;
  level?: string;
  timestamp?: string;
  summary?: string;
}

function toolLabel(tool: string) {
  return {
    get_wazuh_alerts: "讀取告警",
    search_security_events: "搜尋事件",
    get_wazuh_agents: "查設備",
    get_wazuh_running_agents: "查在線設備",
    check_agent_health: "查設備健康",
    get_agent_processes: "查程序",
    get_agent_ports: "查網路埠",
    get_wazuh_cluster_health: "查 Wazuh 健康",
  }[tool] || tool;
}

function toolSummary(item: InvestigationEvidence) {
  const args = item.args || {};
  if (item.tool === "search_security_events") {
    const srcip = typeof args.srcip === "string" ? args.srcip : "";
    const range = typeof args.time_range === "string" ? args.time_range : "指定時間";
    return srcip ? `已查來源 IP ${srcip} 在 ${range} 內的相關事件。` : `已搜尋 ${range} 內的安全事件。`;
  }
  if (item.tool === "get_wazuh_alerts") return "已讀取 Wazuh 告警清單。";
  if (item.tool === "get_wazuh_running_agents") return "已確認目前在線的受監控電腦。";
  if (item.tool === "get_wazuh_agents") return "已查詢受監控電腦清單或指定電腦資料。";
  if (item.tool === "check_agent_health") return "已確認指定電腦是否在線與健康。";
  if (item.tool === "get_agent_processes") return "已查詢指定電腦上的執行中程序。";
  if (item.tool === "get_agent_ports") return "已查詢指定電腦目前開放的網路埠。";
  if (item.tool === "get_wazuh_cluster_health") return "已檢查 Wazuh 平台健康狀態。";
  return "已查詢一項 Wazuh 資料。";
}

function MessageBubble({ message }: { message: InvestigationMessage }) {
  const isUser = message.role === "user";
  return (
    <div className={cn("flex gap-3", isUser && "justify-end")}>
      {!isUser && (
        <div className="flex size-8 shrink-0 items-center justify-center rounded-lg bg-primary/10">
          <Bot className="size-4 text-primary" />
        </div>
      )}
      <div
        className={cn(
          "max-w-[min(760px,85%)] rounded-lg px-4 py-3 text-sm leading-6 shadow-sm",
          isUser
            ? "bg-primary text-primary-foreground"
            : "border border-border bg-card text-card-foreground"
        )}
      >
        {message.content.split("\n").map((line, index) => (
          <p key={`${line}-${index}`} className={cn(index > 0 && "mt-2")}>
            {line || "\u00a0"}
          </p>
        ))}
      </div>
    </div>
  );
}

function EvidenceList({ evidence }: { evidence: InvestigationEvidence[] }) {
  if (!evidence.length) {
    return (
      <div className="flex h-full min-h-48 items-center justify-center rounded-lg border border-dashed text-sm text-muted-foreground">
        尚未查詢 Wazuh 資料
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {evidence.map((item, index) => (
        <Card key={`${item.tool}-${index}`} className="border">
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between gap-3">
              <CardTitle className="flex items-center gap-2 text-sm">
                <Wrench className="size-4 text-primary" />
                {toolLabel(item.tool)}
              </CardTitle>
              <Badge variant="outline">#{index + 1}</Badge>
            </div>
          </CardHeader>
          <CardContent className="space-y-2 text-xs">
            <p className="text-sm leading-6 text-muted-foreground">{toolSummary(item)}</p>
            {item.result_preview && (
              <details className="rounded-md border bg-muted/40 p-2">
                <summary className="cursor-pointer font-medium text-foreground">
                  IT 原始查詢紀錄
                </summary>
                <pre className="mt-2 max-h-32 overflow-auto whitespace-pre-wrap text-muted-foreground">
                  {JSON.stringify(item.args || {}, null, 2)}
                  {"\n\n"}
                  {item.result_preview}
                </pre>
              </details>
            )}
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

export default function InvestigationPage() {
  const [context, setContext] = useState<InvestigationContext>({});
  const [messages, setMessages] = useState<InvestigationMessage[]>([
    {
      role: "assistant",
      content: "請從某筆資安事件點進來查證，或輸入明確的電腦、來源 IP、時間範圍。一般告警會先由 LLM 翻成白話；這裡只在需要更多線索時才查 Wazuh。",
    },
  ]);
  const [evidence, setEvidence] = useState<InvestigationEvidence[]>([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const inputRef = useRef<HTMLTextAreaElement | null>(null);

  const canSend = useMemo(() => input.trim().length > 0 && !loading, [input, loading]);
  const contextualExamples = useMemo(() => {
    if (!context.alertId) return examples;
    const agent = context.agentName || "這台電腦";
    return [
      "這筆事件是不是需要立刻處理？",
      context.sourceIp ? `${context.sourceIp} 最近 7 天還有攻擊其他電腦嗎？` : "",
      `${agent} 最近 24 小時還有其他異常嗎？`,
      `${agent} 現在是否在線？`,
      "產生一份給 IT 的調查摘要。",
    ].filter(Boolean);
  }, [context]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      const params = new URLSearchParams(window.location.search);
      const nextContext: InvestigationContext = {
        alertId: params.get("alert_id") || undefined,
        agentId: params.get("agent_id") || undefined,
        agentName: params.get("agent_name") || undefined,
        agentIp: params.get("agent_ip") || undefined,
        sourceIp: params.get("source_ip") || undefined,
        ruleId: params.get("rule_id") || undefined,
        level: params.get("level") || undefined,
        timestamp: params.get("timestamp") || undefined,
        summary: params.get("summary") || undefined,
      };
      setContext(nextContext);
      if (nextContext.alertId) {
        const lines = [
          "這裡已經帶入剛才那筆資安事件。",
          nextContext.summary ? `事件：${nextContext.summary}` : "",
          nextContext.agentName ? `電腦：${nextContext.agentName}` : "",
          nextContext.agentId ? `Agent ID：${nextContext.agentId}` : "",
          nextContext.sourceIp ? `來源 IP：${nextContext.sourceIp}` : "",
          "這筆告警已先完成白話摘要。若需要更多線索，再點下方問題啟動 MCP 查 Wazuh 紀錄。",
        ].filter(Boolean);
        setMessages([{ role: "assistant", content: lines.join("\n") }]);
      }
    }, 0);
    return () => window.clearTimeout(timer);
  }, []);

  function buildContextQuestion(question: string) {
    if (!context.alertId) return question;
    const facts = [
      `問題：${question}`,
      "",
      "請針對這筆 Wazuh 事件調查：",
      context.summary ? `事件摘要：${context.summary}` : "",
      context.agentId ? `Agent ID：${context.agentId}` : "",
      context.agentName ? `電腦名稱：${context.agentName}` : "",
      context.agentIp ? `電腦 IP：${context.agentIp}` : "",
      context.sourceIp ? `來源 IP：${context.sourceIp}` : "",
      context.ruleId ? `Rule ID：${context.ruleId}` : "",
      context.level ? `Rule level：${context.level}` : "",
      context.timestamp ? `發生時間：${context.timestamp}` : "",
      "",
      "回答時請用白話繁體中文，先講管理者現在要不要找 IT 立刻處理；不要說你已經封鎖、隔離或變更任何設備。",
    ].filter(Boolean);
    return facts.join("\n");
  }

  async function submit(question?: string) {
    const content = (question ?? input).trim();
    if (!content || loading) return;

    const sentContent = buildContextQuestion(content);
    const nextMessages = [...messages, { role: "user" as const, content }];
    const apiMessages = [...messages, { role: "user" as const, content: sentContent }];
    setMessages(nextMessages);
    setInput("");
    setLoading(true);
    setEvidence([]);

    try {
      const response = await sendInvestigationMessage(apiMessages);
      setMessages([...nextMessages, { role: "assistant", content: response.answer_zh }]);
      setEvidence(response.evidence || []);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      setMessages([
        ...nextMessages,
        { role: "assistant", content: `調查失敗：${message}` },
      ]);
      toast.error("調查失敗", { description: message });
    } finally {
      setLoading(false);
      window.setTimeout(() => inputRef.current?.focus(), 0);
    }
  }

  function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void submit();
  }

  return (
    <div className="flex h-full flex-col">
      <header className="flex items-center justify-between border-b border-border bg-card px-6 py-4">
        <div className="flex items-center gap-3">
          <div className="flex size-10 items-center justify-center rounded-lg bg-primary/10">
            <MessageSquareText className="size-5 text-primary" />
          </div>
          <div>
            <h1 className="text-xl font-semibold">MCP 查證</h1>
            <p className="text-sm text-muted-foreground">需要更多線索時，才透過 MCP 查 Wazuh</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant="outline" className="gap-1.5">
            <ShieldCheck className="size-3.5" />
            只查詢
          </Badge>
          <ThemeToggle />
        </div>
      </header>

      <main className="grid min-h-0 flex-1 grid-cols-1 gap-0 lg:grid-cols-[minmax(0,1fr)_360px]">
        <section className="flex min-h-0 flex-col border-r border-border">
          <div className="flex-1 overflow-auto p-6">
            <div className="mx-auto flex max-w-4xl flex-col gap-4">
              <Card className="border-amber-200 bg-amber-50 text-amber-950 dark:border-amber-900/50 dark:bg-amber-950/20 dark:text-amber-100">
                <CardContent className="p-4 text-sm leading-6">
                  告警會先由 LLM 翻成白話；這頁是按需 MCP 查證工具。送出問題後才會讀取 Wazuh 紀錄，不會封鎖 IP、不會隔離電腦，也不會修改任何系統設定。
                </CardContent>
              </Card>
              {context.alertId && (
                <Card className="border-primary/20 bg-primary/5">
                  <CardContent className="grid gap-3 p-4 text-sm sm:grid-cols-2">
                    <div className="sm:col-span-2">
                      <div className="text-xs font-medium text-muted-foreground">LLM 白話摘要</div>
                      <div className="mt-1 font-medium">{context.summary || "Wazuh 告警"}</div>
                    </div>
                    <div>
                      <div className="text-xs font-medium text-muted-foreground">電腦</div>
                      <div>{context.agentName || "-"}{context.agentId ? ` / ${context.agentId}` : ""}</div>
                    </div>
                    <div>
                      <div className="text-xs font-medium text-muted-foreground">來源 IP</div>
                      <div>{context.sourceIp || "-"}</div>
                    </div>
                    <div>
                      <div className="text-xs font-medium text-muted-foreground">Rule</div>
                      <div>{[context.ruleId, context.level ? `level ${context.level}` : ""].filter(Boolean).join(" / ") || "-"}</div>
                    </div>
                    <div>
                      <div className="text-xs font-medium text-muted-foreground">時間</div>
                      <div>{context.timestamp ? new Date(context.timestamp).toLocaleString("zh-TW") : "-"}</div>
                    </div>
                  </CardContent>
                </Card>
              )}
              {messages.map((message, index) => (
                <MessageBubble key={`${message.role}-${index}`} message={message} />
              ))}
              {loading && (
                <div className="flex gap-3">
                  <div className="flex size-8 shrink-0 items-center justify-center rounded-lg bg-primary/10">
                    <Bot className="size-4 text-primary" />
                  </div>
                  <div className="flex items-center gap-2 rounded-lg border border-border bg-card px-4 py-3 text-sm text-muted-foreground">
                    <Loader2 className="size-4 animate-spin" />
                    正在透過 MCP 查 Wazuh
                  </div>
                </div>
              )}
            </div>
          </div>

          <div className="border-t border-border bg-card p-4">
            <div className="mx-auto max-w-4xl space-y-3">
              <div className="flex flex-wrap gap-2">
                {contextualExamples.map((example) => (
                  <Button
                    key={example}
                    type="button"
                    variant="outline"
                    size="sm"
                    disabled={loading}
                    onClick={() => {
                      void submit(example);
                    }}
                  >
                    {example}
                  </Button>
                ))}
              </div>
              <form onSubmit={onSubmit} className="flex items-end gap-2">
                <Textarea
                  ref={inputRef}
                  value={input}
                  onChange={(event) => setInput(event.target.value)}
                  onKeyDown={(event) => {
                    if (event.key === "Enter" && !event.shiftKey) {
                      event.preventDefault();
                      void submit();
                    }
                  }}
                  className="max-h-40 min-h-20 resize-none"
                  placeholder="例如：查這台電腦最近 24 小時是否還有異常"
                  disabled={loading}
                />
                <Button type="submit" size="icon-lg" disabled={!canSend} aria-label="送出">
                  {loading ? <Loader2 className="animate-spin" /> : <Send />}
                </Button>
              </form>
            </div>
          </div>
        </section>

        <aside className="min-h-0 overflow-auto bg-muted/20 p-4">
          <div className="mb-3 flex items-center gap-2 text-sm font-medium">
            <AlertTriangle className="size-4 text-amber-600" />
            MCP 查詢紀錄
          </div>
          <EvidenceList evidence={evidence} />
        </aside>
      </main>
    </div>
  );
}

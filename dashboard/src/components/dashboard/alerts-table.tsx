"use client";

import { Fragment, useMemo, useState } from "react";
import { format } from "date-fns";
import { zhTW } from "date-fns/locale";
import {
  AlertCircle,
  AlertTriangle,
  Info,
  ShieldAlert,
  CheckCircle2,
  XCircle,
  ChevronDown,
  ChevronUp,
  Server,
  Filter,
  Search,
  Loader2,
} from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { TechnicalAlertDetails } from "@/components/dashboard/technical-alert-details";
import { sendInvestigationMessage } from "@/lib/api";
import type { Alert, SeverityLevel, AlertStatus, InvestigationEvidence } from "@/lib/types";
import { severityLabels, statusLabels } from "@/lib/labels";
import { useInvestigationSessions } from "@/lib/use-investigation-sessions";
import { toast } from "sonner";

interface AlertsTableProps {
  alerts: Alert[];
  onStatusChange?: (alertId: string, newStatus: AlertStatus) => void;
}

interface AlertRecordGroup {
  key: string;
  primary: Alert;
  alerts: Alert[];
}

const getSeverityIcon = (severity: SeverityLevel) => {
  switch (severity) {
    case "critical":
      return <ShieldAlert className="size-4 text-critical" />;
    case "high":
      return <AlertTriangle className="size-4 text-high" />;
    case "medium":
      return <Info className="size-4 text-medium" />;
    case "low":
      return <AlertCircle className="size-4 text-low" />;
  }
};

const getSeverityBadgeClass = (severity: SeverityLevel) => {
  switch (severity) {
    case "critical":
      return "bg-critical text-critical-foreground hover:bg-critical/80";
    case "high":
      return "bg-high text-high-foreground hover:bg-high/80";
    case "medium":
      return "bg-medium text-medium-foreground hover:bg-medium/80";
    case "low":
      return "bg-low text-low-foreground hover:bg-low/80";
  }
};

const getStatusBadgeClass = (status: AlertStatus) => {
  switch (status) {
    case "pending":
      return "bg-amber-50 text-amber-700 border-amber-200 dark:bg-amber-950/30 dark:text-amber-300 dark:border-amber-900";
    case "acknowledged":
      return "bg-primary/10 text-primary border-primary/20";
    case "resolved":
      return "bg-success/10 text-success border-success/20";
    case "false_positive":
      return "bg-muted text-muted-foreground border-muted";
  }
};

const statusLabelForRecord = (status: AlertStatus) => {
  if (status === "pending") return "IT 待確認";
  return statusLabels[status];
};

const groupKeyForAlert = (alert: Alert) => {
  const family = alert.rule_id || alert.rule_description || alert.summary;
  const actor = alert.source_ip || alert.iocs?.find((ioc) => /\b(?:\d{1,3}\.){3}\d{1,3}\b/.test(ioc)) || "";
  return [alert.agent_name, family, actor, alert.status].join("|").toLowerCase();
};

const groupAlerts = (alerts: Alert[]) => {
  const groups = new Map<string, AlertRecordGroup>();
  alerts.forEach((alert) => {
    const key = groupKeyForAlert(alert);
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
  if (alerts.length <= 1) {
    return format(new Date(alerts[0].timestamp), "MM/dd HH:mm", { locale: zhTW });
  }
  const sorted = [...alerts].sort(
    (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
  );
  const first = format(new Date(sorted[0].timestamp), "MM/dd HH:mm", { locale: zhTW });
  const last = format(new Date(sorted[sorted.length - 1].timestamp), "MM/dd HH:mm", { locale: zhTW });
  return `${first} - ${last}`;
};

const firstIpLike = (alert: Alert) => {
  if (alert.source_ip) return alert.source_ip;
  const text = [alert.summary, alert.rule_description, alert.root_cause, ...(alert.iocs || [])].join(" ");
  return text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/)?.[0] || "";
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
  return [
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
  ].filter(Boolean).join("\n");
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

export function AlertsTable({ alerts, onStatusChange }: AlertsTableProps) {
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [filterSeverity, setFilterSeverity] = useState<SeverityLevel | "all">("all");
  const [filterStatus, setFilterStatus] = useState<AlertStatus | "all">("all");
  const [filterEndpoint, setFilterEndpoint] = useState("all");
  const [investigatingAlert, setInvestigatingAlert] = useState<Alert | null>(null);
  const [investigationLoading, setInvestigationLoading] = useState(false);
  const { getSession, saveSession } = useInvestigationSessions();

  const endpointOptions = useMemo(
    () => Array.from(new Set(alerts.map((alert) => alert.agent_name).filter(Boolean))).sort(),
    [alerts]
  );

  const filteredAlerts = alerts.filter((alert) => {
    if (filterSeverity !== "all" && alert.severity !== filterSeverity) return false;
    if (filterStatus !== "all" && alert.status !== filterStatus) return false;
    if (filterEndpoint !== "all" && alert.agent_name !== filterEndpoint) return false;
    return true;
  });
  const groupedAlerts = groupAlerts(filteredAlerts);

  const handleStatusChange = (alertId: string, newStatus: AlertStatus) => {
    onStatusChange?.(alertId, newStatus);
    toast.success(`告警狀態已更新為「${statusLabelForRecord(newStatus)}」`);
  };

  const openInvestigation = (alert: Alert) => {
    setSelectedAlert(null);
    setInvestigatingAlert(alert);
  };

  const runInvestigation = async (question: string) => {
    if (!investigatingAlert || investigationLoading) return;
    const sessionKey = `alert:${investigatingAlert.id}`;
    const currentSession = getSession(sessionKey);
    const prompt = buildInvestigationPrompt(investigatingAlert, question);
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

  const investigationSession = getSession(investigatingAlert ? `alert:${investigatingAlert.id}` : "");

  return (
    <>
      <Card>
        <CardHeader>
          <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <CardTitle>告警紀錄</CardTitle>
              <CardDescription>
                共 {filteredAlerts.length} 筆事件，已合併為 {groupedAlerts.length} 組供 IT 或資安顧問查證
                {filteredAlerts.filter((a) => a.status === "pending").length > 0 && (
                  <span className="ml-1 text-muted-foreground">
                    ({filteredAlerts.filter((a) => a.status === "pending").length} 筆尚未歸檔)
                  </span>
                )}
              </CardDescription>
            </div>
            <div className="flex flex-wrap gap-2">
              <label className="inline-flex h-8 items-center gap-1.5 rounded-lg border border-border bg-background px-2.5 text-sm font-medium">
                <Server className="size-4 text-muted-foreground" />
                <span>端點：</span>
                <select
                  value={filterEndpoint}
                  onChange={(event) => setFilterEndpoint(event.target.value)}
                  className="max-w-48 bg-transparent text-sm font-medium outline-none"
                  aria-label="端點篩選"
                >
                  <option value="all">全部</option>
                  {endpointOptions.map((endpoint) => (
                    <option key={endpoint} value={endpoint}>
                      {endpoint}
                    </option>
                  ))}
                </select>
              </label>
              <DropdownMenu>
                <DropdownMenuTrigger render={<Button variant="outline" size="sm" />}>
                  <Filter data-icon="inline-start" />
                  嚴重程度
                </DropdownMenuTrigger>
                <DropdownMenuContent>
                  <DropdownMenuGroup>
                    <DropdownMenuItem onClick={() => setFilterSeverity("all")}>
                      全部
                    </DropdownMenuItem>
                    <DropdownMenuItem onClick={() => setFilterSeverity("critical")}>
                      危急
                    </DropdownMenuItem>
                    <DropdownMenuItem onClick={() => setFilterSeverity("high")}>
                      高
                    </DropdownMenuItem>
                    <DropdownMenuItem onClick={() => setFilterSeverity("medium")}>
                      中
                    </DropdownMenuItem>
                    <DropdownMenuItem onClick={() => setFilterSeverity("low")}>
                      低
                    </DropdownMenuItem>
                  </DropdownMenuGroup>
                </DropdownMenuContent>
              </DropdownMenu>
              <DropdownMenu>
                <DropdownMenuTrigger render={<Button variant="outline" size="sm" />}>
                  <Filter data-icon="inline-start" />
                  狀態
                </DropdownMenuTrigger>
                <DropdownMenuContent>
                  <DropdownMenuGroup>
                    <DropdownMenuItem onClick={() => setFilterStatus("all")}>
                      全部
                    </DropdownMenuItem>
                    <DropdownMenuItem onClick={() => setFilterStatus("pending")}>
                      IT 待確認
                    </DropdownMenuItem>
                    <DropdownMenuItem onClick={() => setFilterStatus("acknowledged")}>
                      已確認
                    </DropdownMenuItem>
                    <DropdownMenuItem onClick={() => setFilterStatus("resolved")}>
                      已解決
                    </DropdownMenuItem>
                    <DropdownMenuItem onClick={() => setFilterStatus("false_positive")}>
                      誤報
                    </DropdownMenuItem>
                  </DropdownMenuGroup>
                </DropdownMenuContent>
              </DropdownMenu>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <ScrollArea className="h-[calc(100vh-22rem)] min-h-[520px]">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-[100px]">嚴重程度</TableHead>
                  <TableHead>描述</TableHead>
                  <TableHead className="hidden md:table-cell">端點</TableHead>
                  <TableHead className="hidden lg:table-cell">時間</TableHead>
                  <TableHead>狀態</TableHead>
                  <TableHead className="w-[50px]"></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {groupedAlerts.map((group) => {
                  const alert = group.primary;
                  return (
                  <Fragment key={group.key}>
                    <TableRow
                      className="cursor-pointer hover:bg-muted/50"
                      onClick={() => setSelectedAlert(alert)}
                    >
                      <TableCell>
                        <Badge className={getSeverityBadgeClass(alert.severity)}>
                          {getSeverityIcon(alert.severity)}
                          <span className="ml-1">{severityLabels[alert.severity]}</span>
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <div className="font-medium">{alert.summary || alert.rule_description}</div>
                        <div className="text-sm text-muted-foreground line-clamp-1">
                          {alert.business_impact}
                        </div>
                        {group.alerts.length > 1 && (
                          <div className="mt-1 text-xs text-muted-foreground">
                            同類事件 {group.alerts.length} 次
                          </div>
                        )}
                      </TableCell>
                      <TableCell className="hidden md:table-cell">
                        <div className="flex items-center gap-2">
                          <Server className="size-4 text-muted-foreground" />
                          <span>{alert.agent_name}</span>
                        </div>
                      </TableCell>
                      <TableCell className="hidden lg:table-cell text-muted-foreground">
                        {formatGroupTimeRange(group.alerts)}
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className={getStatusBadgeClass(alert.status)}>
                          {statusLabelForRecord(alert.status)}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="size-8"
                          onClick={(e) => {
                            e.stopPropagation();
                            setExpandedId(expandedId === group.key ? null : group.key);
                          }}
                        >
                          {expandedId === group.key ? (
                            <ChevronUp className="size-4" />
                          ) : (
                            <ChevronDown className="size-4" />
                          )}
                        </Button>
                      </TableCell>
                    </TableRow>
                    {expandedId === group.key && (
                      <TableRow key={`${group.key}-expanded`}>
                        <TableCell colSpan={6} className="bg-muted/30 p-4">
                          {group.alerts.length > 1 && (
                            <div className="mb-4 rounded-md border bg-background p-3 text-sm">
                              <div className="font-medium">同類事件已合併</div>
                              <div className="mt-1 text-muted-foreground">
                                共 {group.alerts.length} 次，時間：{formatGroupTimeRange(group.alerts)}
                              </div>
                            </div>
                          )}
                          <div className="grid gap-4 md:grid-cols-2">
                            <div>
                              <h4 className="mb-2 font-semibold">業務影響</h4>
                              <p className="text-sm text-muted-foreground">
                                {alert.business_impact}
                              </p>
                            </div>
                            <div>
                              <h4 className="mb-2 font-semibold">建議處理步驟</h4>
                              <p className="whitespace-pre-line text-sm text-muted-foreground">
                                {alert.recommended_action}
                              </p>
                            </div>
                          </div>
                          <div className="mt-4">
                            <TechnicalAlertDetails alert={alert} compact />
                          </div>
                          <div className="mt-4 flex flex-wrap gap-2">
                            <Button
                              type="button"
                              variant="secondary"
                              size="sm"
                              onClick={(event) => {
                                event.stopPropagation();
                                openInvestigation(alert);
                              }}
                            >
                              <Search data-icon="inline-start" />
                              深入調查
                            </Button>
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => group.alerts.forEach((item) => handleStatusChange(item.id, "acknowledged"))}
                            >
                              <CheckCircle2 data-icon="inline-start" />
                              正常操作
                            </Button>
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => group.alerts.forEach((item) => handleStatusChange(item.id, "resolved"))}
                            >
                              <CheckCircle2 data-icon="inline-start" />
                              已處理
                            </Button>
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => group.alerts.forEach((item) => handleStatusChange(item.id, "false_positive"))}
                            >
                              <XCircle data-icon="inline-start" />
                              誤報
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    )}
                  </Fragment>
                  );
                })}
              </TableBody>
            </Table>
          </ScrollArea>
        </CardContent>
      </Card>

      <Dialog open={!!selectedAlert} onOpenChange={() => setSelectedAlert(null)}>
        <DialogContent className="max-h-[88vh] w-[min(1120px,calc(100vw-3rem))] overflow-y-auto p-6 sm:max-w-[min(1120px,calc(100vw-3rem))]">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 pr-8 text-lg">
              {selectedAlert && getSeverityIcon(selectedAlert.severity)}
              {selectedAlert?.summary || selectedAlert?.rule_description}
            </DialogTitle>
            <DialogDescription>
              規則 ID: {selectedAlert?.rule_id}
              {selectedAlert?.rule_description ? ` / ${selectedAlert.rule_description}` : ""}
            </DialogDescription>
          </DialogHeader>
          {selectedAlert && (
            <div className="space-y-4">
              <div className="flex flex-wrap gap-2">
                <Badge className={getSeverityBadgeClass(selectedAlert.severity)}>
                  {severityLabels[selectedAlert.severity]}
                </Badge>
                <Badge variant="outline" className={getStatusBadgeClass(selectedAlert.status)}>
                  {statusLabelForRecord(selectedAlert.status)}
                </Badge>
              </div>
              
              <Separator />
              
              <div className="grid gap-4 lg:grid-cols-[minmax(0,1.2fr)_360px]">
                <div className="space-y-4">
                  <div className="rounded-lg border bg-background p-4">
                    <h4 className="mb-2 font-semibold">摘要</h4>
                    <p className="text-sm text-muted-foreground">{selectedAlert.summary}</p>
                  </div>

                  <div className="rounded-lg border bg-background p-4">
                    <h4 className="mb-2 font-semibold">業務影響</h4>
                    <p className="text-sm text-muted-foreground">{selectedAlert.business_impact}</p>
                  </div>

                  <div className="rounded-lg border bg-background p-4">
                    <h4 className="mb-2 font-semibold">建議處理步驟</h4>
                    <p className="whitespace-pre-line text-sm text-muted-foreground">
                      {selectedAlert.recommended_action}
                    </p>
                  </div>
                </div>

                <div className="rounded-lg border bg-muted/30 p-4">
                  <h4 className="mb-3 font-semibold">事件資訊</h4>
                  <div className="space-y-3 text-sm">
                    <div>
                      <p className="text-xs font-medium text-muted-foreground">端點</p>
                      <p>{selectedAlert.agent_name}</p>
                    </div>
                    <div>
                      <p className="text-xs font-medium text-muted-foreground">端點 IP</p>
                      <p>{selectedAlert.agent_ip || "-"}</p>
                    </div>
                    <div>
                      <p className="text-xs font-medium text-muted-foreground">來源 IP</p>
                      <p>{selectedAlert.source_ip || "-"}</p>
                    </div>
                    <div>
                      <p className="text-xs font-medium text-muted-foreground">時間</p>
                      <p>{format(new Date(selectedAlert.timestamp), "yyyy/MM/dd HH:mm:ss", { locale: zhTW })}</p>
                    </div>
                    <div>
                      <p className="text-xs font-medium text-muted-foreground">Rule</p>
                      <p>{selectedAlert.rule_id}{selectedAlert.rule_level ? ` / level ${selectedAlert.rule_level}` : ""}</p>
                    </div>
                  </div>
                </div>
              </div>

              <TechnicalAlertDetails alert={selectedAlert} />
              
              <Separator />
              
              <div className="flex flex-wrap gap-2">
                <Button
                  type="button"
                  variant="secondary"
                  onClick={() => openInvestigation(selectedAlert)}
                >
                  <Search data-icon="inline-start" />
                  深入調查
                </Button>
                <Button onClick={() => handleStatusChange(selectedAlert.id, "acknowledged")}>
                  <CheckCircle2 data-icon="inline-start" />
                  正常操作
                </Button>
                <Button variant="secondary" onClick={() => handleStatusChange(selectedAlert.id, "resolved")}>
                  <CheckCircle2 data-icon="inline-start" />
                  已處理
                </Button>
                <Button variant="outline" onClick={() => handleStatusChange(selectedAlert.id, "false_positive")}>
                  <XCircle data-icon="inline-start" />
                  誤報
                </Button>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>

      <Sheet
        open={Boolean(investigatingAlert)}
        onOpenChange={(open) => {
          if (!open) setInvestigatingAlert(null);
        }}
      >
        <SheetContent className="w-[min(760px,calc(100vw-1rem))] gap-0 p-0 sm:max-w-none">
          <SheetHeader className="border-b pr-12">
            <SheetTitle>深入調查</SheetTitle>
            <SheetDescription>
              留在告警紀錄流程內查 Wazuh 紀錄；這裡只查詢，不會封鎖、隔離或修改設定。
            </SheetDescription>
          </SheetHeader>

          {investigatingAlert && (
            <div className="flex min-h-0 flex-1 flex-col">
              <div className="space-y-4 overflow-auto p-4">
                <div className="rounded-lg border bg-muted/40 p-4">
                  <div className="text-xs font-medium text-muted-foreground">正在調查的事件</div>
                  <div className="mt-1 text-base font-semibold">
                    {investigatingAlert.summary || investigatingAlert.rule_description}
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
                      <div>{statusLabelForRecord(investigatingAlert.status)}</div>
                    </div>
                  </div>
                </div>

                <div className="rounded-lg border border-amber-200 bg-amber-50 p-3 text-sm leading-6 text-amber-950 dark:border-amber-900/50 dark:bg-amber-950/20 dark:text-amber-100">
                  調查只會讀取 Wazuh 紀錄並整理摘要，不會執行封鎖、隔離、停用帳號或修改設定。
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
                      尚未開始調查。點上方問題後，系統會查 Wazuh 並把結果整理在這裡。
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
                    <summary className="cursor-pointer text-sm font-medium">IT 查詢紀錄</summary>
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
                      handleStatusChange(investigatingAlert.id, "acknowledged");
                      setInvestigatingAlert(null);
                    }}
                  >
                    <CheckCircle2 data-icon="inline-start" />
                    正常操作
                  </Button>
                  <Button
                    variant="outline"
                    onClick={() => {
                      handleStatusChange(investigatingAlert.id, "resolved");
                      setInvestigatingAlert(null);
                    }}
                  >
                    <CheckCircle2 data-icon="inline-start" />
                    已處理
                  </Button>
                  <Button
                    variant="outline"
                    onClick={() => {
                      handleStatusChange(investigatingAlert.id, "false_positive");
                      setInvestigatingAlert(null);
                    }}
                  >
                    <XCircle data-icon="inline-start" />
                    誤報
                  </Button>
                </div>
                <Button variant="ghost" onClick={() => setInvestigatingAlert(null)}>
                  回到告警紀錄
                </Button>
              </SheetFooter>
            </div>
          )}
        </SheetContent>
      </Sheet>
    </>
  );
}

"use client";

import {
  AlertTriangle,
  ShieldAlert,
  CheckCircle2,
  XCircle,
  Wrench,
  ChevronDown,
} from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { TechnicalAlertDetails } from "@/components/dashboard/technical-alert-details";
import type { Alert, AlertStatus } from "@/lib/types";
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

export function ActionableAlerts({ alerts, onStatusChange }: ActionableAlertsProps) {
  const alertGroups = groupPendingAlerts(alerts);
  
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

  if (alertGroups.length === 0) {
    return (
      <Card>
        <CardContent className="flex flex-col items-center justify-center py-12 text-center">
          <CheckCircle2 className="mb-4 size-16 text-success" />
          <h3 className="text-xl font-semibold">沒有待處理事項</h3>
          <p className="mt-2 text-muted-foreground">
            目前沒有需要您決定的資安事件
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <AlertTriangle className="size-5 text-high" />
          需要您決定的事項
        </CardTitle>
        <CardDescription>
          先確認是不是公司正常操作；不確定就交給 IT 查證
          {alertGroups.some((group) => group.alerts.length > 1)
            ? "。同一台電腦的同類告警已合併顯示"
            : ""}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {alertGroups.map((group, index) => {
          const alert = group.primary;
          const groupedCount = group.alerts.length;
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
                  {alert.sampledata && (
                    <Badge variant="outline" className="border-blue-300 bg-blue-50 text-blue-700 dark:border-blue-900 dark:bg-blue-950/30 dark:text-blue-200">
                      測試資料
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
                  {alert.source_ip ? ` / 來源 IP：${alert.source_ip}` : ""}
                </p>
                {groupedCount > 1 && (
                  <p className="mt-1 text-xs text-muted-foreground">
                    發生次數：{groupedCount} 次 / 時間：{formatGroupTimeRange(group.alerts)}
                  </p>
                )}
              </div>

              {splitActionLines(alert.recommended_action).length > 0 && (
                <div className="rounded-lg border border-border p-3">
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
              </div>

              <details className="rounded-lg border border-border px-3 py-2">
                <summary className="flex cursor-pointer items-center gap-2 text-sm font-medium">
                  <ChevronDown className="size-4" />
                  IT 詳細資訊
                </summary>
                <div className="mt-3">
                  <TechnicalAlertDetails alert={alert} compact />
                  {groupedCount > 1 && (
                    <div className="mt-3 rounded-md border bg-background p-3 text-xs text-muted-foreground">
                      這張卡合併了 {groupedCount} 筆同類告警。按上方處理按鈕時，會一起更新這些告警的狀態。
                    </div>
                  )}
                </div>
              </details>
            </div>
          </div>
          );
        })}
      </CardContent>
    </Card>
  );
}

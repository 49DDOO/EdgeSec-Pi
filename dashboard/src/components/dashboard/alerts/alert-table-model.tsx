"use client";

import { format } from "date-fns";
import { zhTW } from "date-fns/locale";
import {
  AlertCircle,
  AlertTriangle,
  ChevronDown,
  Info,
  ShieldAlert,
} from "lucide-react";
import { isLoopbackIp } from "@/lib/investigation";
import type { Alert, AlertStatus, SeverityLevel } from "@/lib/types";
import { statusLabels } from "@/lib/labels";

export type AlertDetailView = "details" | "mcp";

export interface AlertRecordGroup {
  key: string;
  primary: Alert;
  alerts: Alert[];
}

export const neutralButtonClass =
  "border-border bg-background text-foreground hover:bg-muted hover:text-foreground";

export const selectedNeutralButtonClass =
  "border-foreground bg-muted text-foreground hover:bg-muted hover:text-foreground";

export const expandablePanelClass =
  "group rounded-lg border bg-background p-4 [&>summary::-webkit-details-marker]:hidden";

export const expandableSummaryClass =
  "flex cursor-pointer list-none items-center justify-between gap-3 rounded-md text-sm font-semibold transition-colors hover:text-foreground";

export const modalTabClass = (active: boolean) =>
  [
    "inline-flex items-center gap-2 border-b-2 px-1 pb-3 text-sm font-medium transition-colors",
    "focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-muted-foreground/40",
    active
      ? "border-foreground text-foreground"
      : "border-transparent text-muted-foreground hover:border-border hover:text-foreground",
  ].join(" ");

export const ExpandHint = () => (
  <>
    <span className="text-xs font-normal text-muted-foreground group-open:hidden">展開</span>
    <span className="hidden text-xs font-normal text-muted-foreground group-open:inline">收合</span>
  </>
);

export const RotatingChevron = () => (
  <ChevronDown className="size-4 transition-transform group-open:rotate-180" />
);

export const getSeverityIcon = (severity: SeverityLevel) => {
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

export const getSeverityBadgeClass = (severity: SeverityLevel) => {
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

export const getStatusBadgeClass = (status: AlertStatus) => {
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

export const statusLabelForRecord = (status: AlertStatus) => {
  if (status === "pending") return "IT 待確認";
  return statusLabels[status];
};

export const currentAlertRawLog = (alert: Alert) =>
  alert.technical_evidence?.raw?.full_log || alert.full_log || "";

const groupKeyForAlert = (alert: Alert) => {
  const family = alert.rule_id || alert.rule_description || alert.summary;
  const actor = alert.source_ip && !isLoopbackIp(alert.source_ip)
    ? alert.source_ip
    : alert.iocs?.find((ioc) => /\b(?:\d{1,3}\.){3}\d{1,3}\b/.test(ioc) && !isLoopbackIp(ioc)) || "";
  return [alert.agent_name, family, actor, alert.status].join("|").toLowerCase();
};

export const groupAlerts = (alerts: Alert[]) => {
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

export const formatGroupTimeRange = (alerts: Alert[]) => {
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

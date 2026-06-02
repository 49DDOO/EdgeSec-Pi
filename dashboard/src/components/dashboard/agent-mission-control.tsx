"use client";

import Link from "next/link";
import {
  Activity,
  Bell,
  BrainCircuit,
  Database,
  ShieldCheck,
  ShieldQuestion,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { bossActionAlerts, itFollowupAlerts } from "@/lib/alert-routing";
import { normalizedSourceKey, sourceLabel } from "@/lib/source-labels";
import type { DashboardSummary } from "@/lib/api";
import type { Alert } from "@/lib/types";
import { cn } from "@/lib/utils";

interface AgentMissionControlProps {
  alerts: Alert[];
  summary: DashboardSummary;
}

function healthLabel(status: "healthy" | "degraded" | "down") {
  if (status === "healthy") return "正常";
  if (status === "degraded") return "需注意";
  return "中斷";
}

function healthTone(status: "healthy" | "degraded" | "down") {
  if (status === "healthy") return "border-success/30 bg-success/10 text-success";
  if (status === "degraded") return "border-medium/40 bg-medium/10 text-medium";
  return "border-destructive/30 bg-destructive/10 text-destructive";
}

export function AgentMissionControl({ alerts, summary }: AgentMissionControlProps) {
  const ownerAlerts = bossActionAlerts(alerts);
  const itAlerts = itFollowupAlerts(alerts);
  const sourceKeys = Array.from(
    new Set(alerts.map((alert) => normalizedSourceKey(alert.siem_source)))
  );
  const connectedSourceCount = Math.max(
    sourceKeys.length,
    summary.systemHealth.wazuh_connection === "connected" ? 1 : 0
  );
  const sourceText = sourceKeys.length > 0
    ? sourceKeys.slice(0, 2).map((source) => sourceLabel(source)).join("、")
    : summary.systemHealth.wazuh_connection === "connected"
      ? "端點偵測來源"
      : "尚未收到來源訊號";
  const agentState = ownerAlerts.length > 0
    ? {
        icon: ShieldQuestion,
        label: `${ownerAlerts.length} 件需要你決定`,
        detail: "Agent 已整理判斷與證據，請先看是否批准處置或交給 IT。",
        tone: "border-high/30 bg-high/10 text-high",
        iconTone: "text-high",
      }
    : {
        icon: ShieldCheck,
        label: "持續守護中",
        detail: itAlerts.length > 0
          ? `${itAlerts.length} 件技術項目已留給 IT 查證，目前沒有老闆待辦。`
          : "目前沒有需要介入的資安決策。",
        tone: "border-success/30 bg-success/10 text-success",
        iconTone: "text-success",
      };
  const AgentStateIcon = agentState.icon;
  const capabilities = [
    {
      label: "感測器",
      value: `${connectedSourceCount} 個來源`,
      detail: sourceText,
      icon: Database,
      href: "/settings/sources",
      tone: summary.systemHealth.wazuh_connection === "connected"
        ? "border-success/30 bg-success/10 text-success"
        : "border-medium/40 bg-medium/10 text-medium",
    },
    {
      label: "判斷腦",
      value: healthLabel(summary.systemHealth.llm_service),
      detail: "AI 風險判斷與中文報告",
      icon: BrainCircuit,
      href: "/settings/ai-model",
      tone: healthTone(summary.systemHealth.llm_service),
    },
    {
      label: "回報通道",
      value: healthLabel(summary.systemHealth.notification_service),
      detail: "Slack / LINE / Email 通知",
      icon: Bell,
      href: "/settings/notifications",
      tone: healthTone(summary.systemHealth.notification_service),
    },
    {
      label: "任務佇列",
      value: `${summary.systemHealth.analysis_queue} 件`,
      detail: "等待 Agent 分析的訊號",
      icon: Activity,
      href: "/settings/status",
      tone: summary.systemHealth.analysis_queue > 0
        ? "border-medium/40 bg-medium/10 text-medium"
        : "border-success/30 bg-success/10 text-success",
    },
  ];

  return (
    <Card>
      <CardHeader className="pb-4">
        <div className="flex flex-col gap-4 xl:flex-row xl:items-center xl:justify-between">
          <div className="min-w-0">
            <CardTitle className="flex items-center gap-2 text-lg">
              <AgentStateIcon className={cn("size-5", agentState.iconTone)} />
              資安 Agent 現況
            </CardTitle>
            <p className="mt-1 max-w-3xl text-sm leading-6 text-muted-foreground">
              Agent 接收雲端與地端來源訊號，整理成需要決策、需要 IT 查證或可歸檔的事件。
            </p>
          </div>
          <div className={cn("rounded-lg border px-4 py-3", agentState.tone)}>
            <div className="text-sm font-semibold text-foreground">{agentState.label}</div>
            <p className="mt-1 text-sm leading-6 text-muted-foreground">{agentState.detail}</p>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <div className="grid gap-2 md:grid-cols-4">
          {capabilities.map((item) => {
            const Icon = item.icon;
            return (
              <Link
                key={item.label}
                href={item.href}
                className="rounded-lg border px-3 py-3 transition hover:border-primary/40 hover:bg-muted/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              >
                <div className="flex items-center gap-2">
                  <span className={cn("flex size-8 shrink-0 items-center justify-center rounded-md border", item.tone)}>
                    <Icon className="size-4" />
                  </span>
                  <div className="min-w-0">
                    <div className="truncate text-sm font-semibold">{item.value}</div>
                    <div className="truncate text-xs text-muted-foreground">{item.label} · {item.detail}</div>
                  </div>
                </div>
              </Link>
            );
          })}
        </div>
      </CardContent>
    </Card>
  );
}

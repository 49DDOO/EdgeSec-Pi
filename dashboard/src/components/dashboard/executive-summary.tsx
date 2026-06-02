"use client";

import Link from "next/link";
import {
  ArrowRight,
  ClipboardCheck,
  ShieldAlert,
  ShieldCheck,
  Users,
} from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { buttonVariants } from "@/components/ui/button";
import { bossActionAlerts, itFollowupAlerts } from "@/lib/alert-routing";
import { normalizedSourceKey, sourceLabel } from "@/lib/source-labels";
import type { RiskSummary, Alert } from "@/lib/types";
import { cn } from "@/lib/utils";

interface ExecutiveSummaryProps {
  data: RiskSummary;
  alerts: Alert[];
  endpointCount: number;
}

export function ExecutiveSummary({ data, alerts, endpointCount }: ExecutiveSummaryProps) {
  const ownerAlerts = bossActionAlerts(alerts);
  const itAlerts = itFollowupAlerts(alerts);
  const criticalPending = ownerAlerts.filter((alert) => alert.severity === "critical");
  const eventSourceKeys = Array.from(new Set(alerts.map((alert) => normalizedSourceKey(alert.siem_source))));
  const eventSourceNames = eventSourceKeys.map((key) => sourceLabel(key));
  const eventSourceSummary = eventSourceNames.length === 0
    ? "尚無事件"
    : eventSourceNames.length === 1
      ? eventSourceNames[0]
      : `${eventSourceNames.length} 個來源`;
  const handledForBoss = itAlerts.length;
  const hiddenByCategoryCount = Math.max(data.total_alerts_today - alerts.length, 0);
  const totalVisibleLabel = hiddenByCategoryCount > 0 ? "目前顯示" : "今日收到";

  const status = (() => {
    if (criticalPending.length > 0) {
      return {
        icon: ShieldAlert,
        eyebrow: "需要今天處理",
        title: `Agent 請你先決定 ${criticalPending.length} 件事`,
        detail: "這些事件可能影響營運。Agent 已先整理判斷與證據，請確認是否批准處置或交給 IT 立刻處理。",
        tone: "text-critical",
        bg: "bg-critical/10",
        border: "border-critical/30",
        cta: "處理緊急待辦",
        href: "#boss-actions",
      };
    }
    if (ownerAlerts.length > 0) {
      return {
        icon: ShieldAlert,
        eyebrow: "需要您判斷",
        title: `Agent 有 ${ownerAlerts.length} 件事要請示`,
        detail: "先看是不是公司允許的登入、測試或異動；不確定就交給 IT，不要直接放行。",
        tone: "text-high",
        bg: "bg-high/10",
        border: "border-high/30",
        cta: "處理老闆待辦",
        href: "#boss-actions",
      };
    }
    return {
      icon: ShieldCheck,
      eyebrow: "目前不用您介入",
      title: "Agent 正在守護，目前不用介入",
      detail: itAlerts.length > 0
        ? `${itAlerts.length} 件技術項目已留在調查紀錄中給 IT 確認，目前沒有需要老闆決定的資安事項。`
        : "目前沒有需要處理的資安事項；Agent 會持續監看已連接的雲端與地端來源。",
      tone: "text-success",
      bg: "bg-success/10",
      border: "border-success/30",
      cta: itAlerts.length > 0 ? "查看 IT 處理狀態" : "查看調查紀錄",
      href: itAlerts.length > 0 ? "/events?status=pending" : "/events",
    };
  })();

  const StatusIcon = status.icon;
  const statItems = [
    {
      href: "#boss-actions",
      icon: ShieldCheck,
      label: "Agent 請示",
      value: `${ownerAlerts.length} 件`,
      valueClassName: ownerAlerts.length > 0 ? "text-high" : "text-success",
      hint: "查看需要決策事項",
    },
    {
      href: "/events?status=pending",
      icon: ClipboardCheck,
      label: "已交給 IT",
      value: `${handledForBoss} 件`,
      valueClassName: "text-foreground",
      hint: "查看 IT 查證狀態",
    },
    {
      href: "/settings/endpoints?section=inventory",
      icon: Users,
      label: "受保護資產",
      value: `${endpointCount} 台`,
      valueClassName: "text-foreground",
      hint: "查看資產清單",
    },
    {
      href: "/events",
      icon: ClipboardCheck,
      label: `${totalVisibleLabel} / Sources`,
      value: `${alerts.length} 件 · ${eventSourceSummary}`,
      valueClassName: "text-foreground text-lg",
      hint: "查看 Agent 調查紀錄",
    },
  ];

  return (
    <Card className={cn("border", status.border)}>
      <CardContent className="p-5">
        <div className="flex flex-col gap-5 lg:flex-row lg:items-center lg:justify-between">
          <div className="flex min-w-0 gap-4">
            <div className={cn("mt-1 flex size-11 shrink-0 items-center justify-center rounded-full", status.bg, status.tone)}>
              <StatusIcon className="size-6" />
            </div>
            <div className="min-w-0">
              <div className={cn("text-sm font-semibold", status.tone)}>{status.eyebrow}</div>
              <h2 className={cn("mt-1 text-3xl font-bold tracking-normal", status.tone)}>
                {status.title}
              </h2>
              <p className="mt-2 max-w-3xl text-base leading-7 text-muted-foreground">
                {status.detail}
              </p>
            </div>
          </div>

          <div className="flex shrink-0 flex-col gap-2 sm:flex-row lg:flex-col">
            <Link href={status.href} className={buttonVariants({ className: "justify-center" })}>
              {status.cta}
              <ArrowRight data-icon="inline-end" />
            </Link>
            {ownerAlerts.length === 0 && itAlerts.length > 0 && (
              <Link
                href="/events?status=pending"
                className={buttonVariants({ variant: "outline", className: "justify-center" })}
              >
                看 IT 查證
              </Link>
            )}
          </div>
        </div>

        <div className="mt-5 grid gap-2 border-t pt-4 sm:grid-cols-2 lg:grid-cols-4">
          {statItems.map((item) => {
            const Icon = item.icon;
            return (
              <Link
                key={item.label}
                href={item.href}
                aria-label={`${item.label}：${item.value}，${item.hint}`}
                className="group rounded-lg border border-transparent p-3 transition hover:border-border hover:bg-muted/50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              >
                <div className="flex items-center justify-between gap-2">
                  <div className="flex min-w-0 items-center gap-2 text-sm text-muted-foreground">
                    <Icon className="size-4 shrink-0" />
                    <span className="truncate">{item.label}</span>
                  </div>
                  <ArrowRight className="size-3.5 shrink-0 text-muted-foreground opacity-0 transition group-hover:opacity-100 group-focus-visible:opacity-100" />
                </div>
                <div className={cn("mt-1 truncate text-2xl font-bold", item.valueClassName)}>
                  {item.value}
                </div>
                <div className="mt-1 text-xs text-muted-foreground opacity-0 transition group-hover:opacity-100 group-focus-visible:opacity-100">
                  {item.hint}
                </div>
              </Link>
            );
          })}
        </div>
      </CardContent>
    </Card>
  );
}

"use client";

import Link from "next/link";
import {
  AlertTriangle,
  CheckCircle2,
  ClipboardList,
  ExternalLink,
  Search,
  ShieldAlert,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { buttonVariants } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { bossActionAlerts, itFollowupAlerts } from "@/lib/alert-routing";
import type { Alert } from "@/lib/types";
import { cn } from "@/lib/utils";

interface TriageCommandCenterProps {
  alerts: Alert[];
}

function countLabel(count: number, unit = "件") {
  return `${count} ${unit}`;
}

export function TriageCommandCenter({ alerts }: TriageCommandCenterProps) {
  const pendingAlerts = alerts.filter((alert) => alert.status === "pending");
  const urgentAlerts = pendingAlerts.filter((alert) => (
    alert.severity === "critical" || alert.severity === "high"
  ));
  const ownerAlerts = bossActionAlerts(alerts);
  const itAlerts = itFollowupAlerts(alerts);
  const acknowledgedAlerts = alerts.filter((alert) => alert.status === "acknowledged");
  const closedToday = alerts.filter((alert) => (
    alert.status === "resolved" || alert.status === "false_positive"
  ));

  const queues = [
    {
      label: "高風險待處理",
      value: urgentAlerts.length,
      detail: "先看 critical / high 且尚未歸檔的事件",
      icon: ShieldAlert,
      href: "/events?status=pending&severity=urgent",
      cta: "處理高風險",
      tone: urgentAlerts.length > 0 ? "border-red-200 bg-red-50/50 text-red-700" : "border-border bg-background text-muted-foreground",
      primary: urgentAlerts.length > 0,
    },
    {
      label: "待查證事件",
      value: pendingAlerts.length,
      detail: "Agent 尚未歸檔、仍需查證的事件佇列",
      icon: ClipboardList,
      href: "/events?status=pending",
      cta: "查看查證狀態",
      tone: pendingAlerts.length > 0 ? "border-amber-200 bg-amber-50/50 text-amber-700" : "border-border bg-background text-muted-foreground",
      primary: urgentAlerts.length === 0 && pendingAlerts.length > 0,
    },
    {
      label: "已交辦 IT",
      value: acknowledgedAlerts.length,
      detail: "已確認需要 IT 後續處理的項目",
      icon: AlertTriangle,
      href: "/events?status=acknowledged",
      cta: "查看交辦",
      tone: "border-border bg-background text-muted-foreground",
      primary: false,
    },
    {
      label: "今日已歸檔",
      value: closedToday.length,
      detail: "已結案或標成誤報的事件",
      icon: CheckCircle2,
      href: "/events?status=resolved",
      cta: "查看結案",
      tone: "border-border bg-background text-muted-foreground",
      primary: false,
    },
  ];

  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
          <div>
            <CardTitle className="flex items-center gap-2 text-lg">
              <ClipboardList className="size-5" />
              Agent 調查主控台
            </CardTitle>
            <p className="mt-1 text-sm text-muted-foreground">
              供 IT 或資安顧問查看 Agent 判斷、查證、交辦與歸檔；首頁只保留需要老闆決定的事項。
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <Badge variant="outline">Agent 請示 {countLabel(ownerAlerts.length)}</Badge>
            <Badge variant="outline">IT 待確認 {countLabel(itAlerts.length)}</Badge>
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid gap-3 lg:grid-cols-4">
          {queues.map((queue) => {
            const Icon = queue.icon;
            return (
              <div key={queue.label} className={cn("rounded-lg border p-4", queue.tone)}>
                <div className="flex items-center justify-between gap-3">
                  <Icon className="size-5 shrink-0" />
                  <div className="text-2xl font-semibold text-foreground">{queue.value}</div>
                </div>
                <div className="mt-3 text-sm font-semibold text-foreground">{queue.label}</div>
                <p className="mt-1 min-h-10 text-xs leading-5 text-muted-foreground">{queue.detail}</p>
                <Link
                  href={queue.href}
                  className={buttonVariants({
                    variant: queue.primary ? "default" : "outline",
                    size: "sm",
                    className: "mt-3 w-full",
                  })}
                >
                  {queue.cta}
                  <ExternalLink data-icon="inline-end" />
                </Link>
              </div>
            );
          })}
        </div>

        <div className="flex flex-col gap-3 rounded-lg border bg-muted/30 p-4 text-sm md:flex-row md:items-center md:justify-between">
          <div>
            <div className="font-semibold">需要更多線索時再問 Agent</div>
            <p className="mt-1 text-muted-foreground">
              單一事件內可直接查；全域查詢適合跨來源、跨資產、跨時間範圍的問題。
            </p>
          </div>
          <Link
            href="/investigation"
            className={buttonVariants({ variant: "outline", className: "shrink-0" })}
          >
            <Search data-icon="inline-start" />
            開啟證據查詢
          </Link>
        </div>
      </CardContent>
    </Card>
  );
}

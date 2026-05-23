"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  Clock,
  HelpCircle,
  RefreshCw,
  ServerCog,
  XCircle,
} from "lucide-react";
import { toast } from "sonner";
import { ThemeToggle } from "@/components/dashboard/theme-toggle";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { fetchServiceStatus } from "@/lib/api";
import type { ServiceCheck, ServiceCheckStatus, ServiceStatusResponse } from "@/lib/types";
import { cn } from "@/lib/utils";

function formatCheckedAt(value?: string) {
  if (!value) return "尚未更新";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat("zh-TW", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).format(date);
}

function statusView(status: ServiceCheckStatus | ServiceStatusResponse["overall"]) {
  switch (status) {
    case "ok":
      return {
        label: "正常",
        icon: CheckCircle2,
        badge: "bg-emerald-600 text-white hover:bg-emerald-600",
        card: "border-emerald-200 bg-emerald-50/40 dark:border-emerald-900 dark:bg-emerald-950/20",
        iconClass: "text-emerald-600",
      };
    case "warn":
      return {
        label: "需確認",
        icon: AlertTriangle,
        badge: "bg-amber-500 text-white hover:bg-amber-500",
        card: "border-amber-200 bg-amber-50/50 dark:border-amber-900 dark:bg-amber-950/20",
        iconClass: "text-amber-600",
      };
    case "fail":
      return {
        label: "需處理",
        icon: XCircle,
        badge: "bg-red-600 text-white hover:bg-red-600",
        card: "border-red-200 bg-red-50/50 dark:border-red-900 dark:bg-red-950/20",
        iconClass: "text-red-600",
      };
    default:
      return {
        label: "未啟用",
        icon: HelpCircle,
        badge: "bg-muted text-muted-foreground hover:bg-muted",
        card: "border-border bg-muted/20",
        iconClass: "text-muted-foreground",
      };
  }
}

function ServiceCard({ service }: { service: ServiceCheck }) {
  const view = statusView(service.status);
  const Icon = view.icon;

  return (
    <Card className={cn("border", view.card)}>
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between gap-4">
          <div className="flex items-start gap-3">
            <Icon className={cn("mt-0.5 size-5 shrink-0", view.iconClass)} />
            <div>
              <CardTitle className="text-base">{service.label_zh}</CardTitle>
              <CardDescription className="mt-1 text-sm">
                {service.summary_zh}
              </CardDescription>
            </div>
          </div>
          <Badge className={view.badge}>{view.label}</Badge>
        </div>
      </CardHeader>
      {(service.next_step_zh || service.detail_zh) && (
        <CardContent className="space-y-2 pt-0 text-sm">
          {service.next_step_zh && (
            <p>
              <span className="font-medium">下一步：</span>
              <span className="text-muted-foreground">{service.next_step_zh}</span>
            </p>
          )}
          {service.detail_zh && (
            <p className="text-xs text-muted-foreground">{service.detail_zh}</p>
          )}
        </CardContent>
      )}
    </Card>
  );
}

export default function StatusPage() {
  const [status, setStatus] = useState<ServiceStatusResponse | null>(null);
  const [loading, setLoading] = useState(true);

  const loadStatus = useCallback(async (showToast = false) => {
    setLoading(true);
    try {
      const next = await fetchServiceStatus();
      setStatus(next);
      if (showToast) toast.success("系統狀態已更新");
    } catch (error) {
      toast.error("讀取系統狀態失敗", {
        description: error instanceof Error ? error.message : String(error),
      });
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    fetchServiceStatus()
      .then((next) => {
        if (!cancelled) setStatus(next);
      })
      .catch((error) => {
        if (!cancelled) {
          toast.error("讀取系統狀態失敗", {
            description: error instanceof Error ? error.message : String(error),
          });
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    const intervalMs = (status?.refresh_interval_s || 15) * 1000;
    const timer = window.setInterval(() => {
      void loadStatus(false);
    }, intervalMs);
    return () => window.clearInterval(timer);
  }, [loadStatus, status?.refresh_interval_s]);

  const overall = statusView(status?.overall || "warn");
  const OverallIcon = overall.icon;
  const counts = useMemo(() => {
    const services = status?.services || [];
    return {
      ok: services.filter((service) => service.status === "ok").length,
      warn: services.filter((service) => service.status === "warn").length,
      fail: services.filter((service) => service.status === "fail").length,
      skip: services.filter((service) => service.status === "skip").length,
    };
  }, [status]);

  return (
    <div className="flex h-full flex-col">
      <header className="flex items-center justify-between border-b border-border bg-card px-6 py-4">
        <div className="flex items-center gap-3">
          <div className="flex size-10 items-center justify-center rounded-lg bg-primary/10">
            <ServerCog className="size-5 text-primary" />
          </div>
          <div>
            <h1 className="text-xl font-semibold">系統狀態</h1>
            <p className="text-sm text-muted-foreground">
              檢查告警接收、AI 分析、Wazuh、進階查詢與通知是否可用
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" onClick={() => loadStatus(true)} disabled={loading}>
            <RefreshCw data-icon="inline-start" className={cn(loading && "animate-spin")} />
            重新整理
          </Button>
          <ThemeToggle />
        </div>
      </header>

      <main className="flex-1 overflow-auto p-6">
        <div className="mx-auto max-w-6xl space-y-6">
          <Card className={cn("border", overall.card)}>
            <CardContent className="grid gap-6 p-6 lg:grid-cols-[1fr_360px]">
              <div className="flex gap-4">
                <OverallIcon className={cn("mt-1 size-8 shrink-0", overall.iconClass)} />
                <div>
                  <div className="text-sm font-medium text-muted-foreground">目前總體狀態</div>
                  <h2 className="mt-1 text-3xl font-semibold">{status?.title_zh || "正在讀取"}</h2>
                  <p className="mt-2 text-muted-foreground">
                    {status?.message_zh || "正在檢查本機服務。"}
                  </p>
                  <p className="mt-3 text-sm font-medium">
                    {status?.next_step_zh || "請稍候。"}
                  </p>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3 text-sm">
                <div className="rounded-lg border bg-card p-3">
                  <div className="text-muted-foreground">正常</div>
                  <div className="mt-1 text-2xl font-semibold text-emerald-600">{counts.ok}</div>
                </div>
                <div className="rounded-lg border bg-card p-3">
                  <div className="text-muted-foreground">需確認</div>
                  <div className="mt-1 text-2xl font-semibold text-amber-600">{counts.warn}</div>
                </div>
                <div className="rounded-lg border bg-card p-3">
                  <div className="text-muted-foreground">需處理</div>
                  <div className="mt-1 text-2xl font-semibold text-red-600">{counts.fail}</div>
                </div>
                <div className="rounded-lg border bg-card p-3">
                  <div className="text-muted-foreground">未啟用</div>
                  <div className="mt-1 text-2xl font-semibold">{counts.skip}</div>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
                <div>
                  <CardTitle>服務檢查</CardTitle>
                  <CardDescription>
                    這一頁每 {status?.refresh_interval_s || 15} 秒自動更新一次；目前用輪詢，不使用 WebSocket。
                  </CardDescription>
                </div>
                <div className="flex items-center gap-2 text-sm text-muted-foreground">
                  <Clock className="size-4" />
                  {formatCheckedAt(status?.checked_at)}
                </div>
              </div>
            </CardHeader>
            <CardContent className="grid gap-4 md:grid-cols-2">
              {(status?.services || []).map((service) => (
                <ServiceCard key={service.id} service={service} />
              ))}
              {!status && (
                <Card className="border-dashed">
                  <CardContent className="p-6 text-sm text-muted-foreground">
                    正在讀取系統狀態...
                  </CardContent>
                </Card>
              )}
            </CardContent>
          </Card>

          {status && (
            <Card>
              <CardHeader>
                <CardTitle>即時指標</CardTitle>
                <CardDescription>給技術窗口確認用，平常只需要看上方狀態。</CardDescription>
              </CardHeader>
              <CardContent className="grid gap-3 text-sm sm:grid-cols-4">
                <div className="rounded-lg border p-3">
                  <div className="text-muted-foreground">分析佇列</div>
                  <div className="mt-1 text-xl font-semibold">
                    {status.metrics.queue_size}/{status.metrics.queue_max}
                  </div>
                </div>
                <div className="rounded-lg border p-3">
                  <div className="text-muted-foreground">背景工人</div>
                  <div className="mt-1 text-xl font-semibold">{status.metrics.workers}</div>
                </div>
                <div className="rounded-lg border p-3">
                  <div className="text-muted-foreground">通知已設定</div>
                  <div className="mt-1 text-xl font-semibold">
                    {status.metrics.notifications_configured}/4
                  </div>
                </div>
                <div className="rounded-lg border p-3">
                  <div className="text-muted-foreground">通知已測通</div>
                  <div className="mt-1 text-xl font-semibold">
                    {status.metrics.notifications_tested}/4
                  </div>
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      </main>
    </div>
  );
}

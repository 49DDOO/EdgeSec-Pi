"use client";

import { useEffect, useState } from "react";
import { ExecutiveSummary } from "@/components/dashboard/executive-summary";
import { ActionableAlerts } from "@/components/dashboard/actionable-alerts";
import { DeviceStatus } from "@/components/dashboard/device-status";
import { AlertTrendChart } from "@/components/dashboard/alert-trend-chart";
import { AlertsTable } from "@/components/dashboard/alerts-table";
import { EndpointsMonitor } from "@/components/dashboard/endpoints-monitor";
import { SystemStatus } from "@/components/dashboard/system-status";
import { NotificationPanel } from "@/components/dashboard/notification-panel";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { ThemeToggle } from "@/components/dashboard/theme-toggle";
import { fetchDashboardSummary, updateAlertStatus } from "@/lib/api";
import type { DashboardSummary } from "@/lib/api";
import type { AlertStatus } from "@/lib/types";
import { LayoutDashboard, AlertCircle, Server, Settings, Wrench, Bell, Loader2 } from "lucide-react";
import { toast } from "sonner";

export default function DashboardPage() {
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [notificationPanelOpen, setNotificationPanelOpen] = useState(false);

  useEffect(() => {
    let active = true;
    fetchDashboardSummary()
      .then((data) => {
        if (!active) return;
        setSummary(data);
        setLoadError(null);
      })
      .catch((error) => {
        if (!active) return;
        setLoadError(error instanceof Error ? error.message : "Dashboard API 無法連線");
      });
    return () => {
      active = false;
    };
  }, []);

  const pendingCount = summary?.alerts.filter((a) => a.status === "pending").length ?? 0;

  const handleStatusChange = async (alertId: string, newStatus: AlertStatus) => {
    if (!summary) return;
    const previous = summary;
    setSummary((prev) => ({
      ...(prev || previous),
      alerts: (prev || previous).alerts.map((alert) =>
        alert.id === alertId ? { ...alert, status: newStatus } : alert
      ),
    }));
    try {
      await updateAlertStatus(alertId, newStatus);
    } catch (error) {
      setSummary(previous);
      toast.error("狀態更新失敗", {
        description: error instanceof Error ? error.message : "請確認橋接服務是否正常",
      });
    }
  };

  const handleNotificationChange = (key: keyof DashboardSummary["notifications"], value: boolean) => {
    setSummary((prev) =>
      prev
        ? {
            ...prev,
            notifications: { ...prev.notifications, [key]: value },
          }
        : prev
    );
  };

  return (
    <div className="flex h-full flex-col">
      {/* Page Header */}
      <header className="flex items-center justify-between border-b border-border bg-card px-6 py-4">
        <div>
          <h1 className="text-xl font-semibold">資安總覽</h1>
          <p className="text-sm text-muted-foreground">
            查看公司整體資安狀況與待處理事項
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="icon"
            className="relative"
            onClick={() => setNotificationPanelOpen(true)}
          >
            <Bell className="size-4" />
            {pendingCount > 0 && (
              <span className="absolute -right-1 -top-1 flex size-5 items-center justify-center rounded-full bg-destructive text-xs text-destructive-foreground">
                {pendingCount}
              </span>
            )}
          </Button>
          <ThemeToggle />
        </div>
      </header>

      {/* Main Content */}
      <main className="flex-1 overflow-auto p-6">
        {!summary && !loadError && (
          <div className="flex min-h-[360px] items-center justify-center rounded-lg border border-dashed border-border">
            <div className="flex items-center gap-3 text-muted-foreground">
              <Loader2 className="size-5 animate-spin" />
              正在讀取 Dashboard 資料...
            </div>
          </div>
        )}

        {loadError && (
          <div className="rounded-lg border border-destructive/30 bg-destructive/5 p-6">
            <h2 className="text-lg font-semibold text-destructive">Dashboard 資料讀取失敗</h2>
            <p className="mt-2 text-sm text-muted-foreground">
              目前不顯示示範資料，避免誤判正式狀態。請先確認 EdgeSec-Pi bridge 是否正常啟動。
            </p>
            <code className="mt-4 block rounded-md bg-muted px-3 py-2 text-sm text-muted-foreground">
              {loadError}
            </code>
          </div>
        )}
        {summary && (
        <Tabs defaultValue="boss" className="space-y-6">
          <TabsList className="grid w-full grid-cols-5 lg:w-auto lg:inline-flex">
            <TabsTrigger value="boss" className="gap-2">
              <LayoutDashboard className="size-4" />
              <span className="hidden sm:inline">總覽</span>
            </TabsTrigger>
            <TabsTrigger value="alerts" className="gap-2">
              <AlertCircle className="size-4" />
              <span className="hidden sm:inline">告警</span>
              {pendingCount > 0 && (
                <span className="ml-1 flex size-5 items-center justify-center rounded-full bg-destructive text-xs text-destructive-foreground">
                  {pendingCount}
                </span>
              )}
            </TabsTrigger>
            <TabsTrigger value="endpoints" className="gap-2">
              <Server className="size-4" />
              <span className="hidden sm:inline">設備</span>
            </TabsTrigger>
            <TabsTrigger value="it" className="gap-2">
              <Wrench className="size-4" />
              <span className="hidden sm:inline">IT 詳細</span>
            </TabsTrigger>
            <TabsTrigger value="system" className="gap-2">
              <Settings className="size-4" />
              <span className="hidden sm:inline">系統</span>
            </TabsTrigger>
          </TabsList>

          {/* 老闆視角 - 簡單明瞭 */}
          <TabsContent value="boss" className="space-y-6">
            <ExecutiveSummary
              data={summary.riskSummary}
              alerts={summary.alerts}
              endpointCount={summary.endpoints.length}
            />
            <div className="grid gap-6 lg:grid-cols-2">
              <ActionableAlerts
                alerts={summary.alerts}
                onStatusChange={handleStatusChange}
              />
              <DeviceStatus endpoints={summary.endpoints} />
            </div>
          </TabsContent>

          {/* 告警頁面 - 簡化版 */}
          <TabsContent value="alerts">
            <ActionableAlerts
              alerts={summary.alerts}
              onStatusChange={handleStatusChange}
            />
          </TabsContent>

          {/* 設備狀態 */}
          <TabsContent value="endpoints">
            <DeviceStatus endpoints={summary.endpoints} />
          </TabsContent>

          {/* IT 詳細視角 - 保留技術細節 */}
          <TabsContent value="it" className="space-y-6">
            <div className="grid gap-6 lg:grid-cols-2">
              <AlertTrendChart data={summary.alertTrends} />
              <EndpointsMonitor endpoints={summary.endpoints} />
            </div>
            <AlertsTable alerts={summary.alerts} onStatusChange={handleStatusChange} />
          </TabsContent>

          {/* 系統設定 */}
          <TabsContent value="system">
            <SystemStatus
              health={summary.systemHealth}
              notifications={summary.notifications}
              onNotificationChange={handleNotificationChange}
            />
          </TabsContent>
        </Tabs>
        )}
      </main>

      <NotificationPanel
        open={notificationPanelOpen}
        onOpenChange={setNotificationPanelOpen}
        alerts={summary?.alerts || []}
      />
    </div>
  );
}

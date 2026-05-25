"use client";

import { useEffect, useMemo, useState } from "react";
import { ExecutiveSummary } from "@/components/dashboard/executive-summary";
import { ActionableAlerts } from "@/components/dashboard/actionable-alerts";
import { DeviceStatus } from "@/components/dashboard/device-status";
import { AlertTrendChart } from "@/components/dashboard/alert-trend-chart";
import { AlertsTable } from "@/components/dashboard/alerts-table";
import { NotificationPanel } from "@/components/dashboard/notification-panel";
import { Button } from "@/components/ui/button";
import { ThemeToggle } from "@/components/dashboard/theme-toggle";
import { bossActionAlerts } from "@/lib/alert-routing";
import { fetchDashboardSummary, updateAlertStatus } from "@/lib/api";
import { filterAlertsByEnabledCategories } from "@/lib/detection-categories";
import type { DashboardSummary } from "@/lib/api";
import type { AlertStatus } from "@/lib/types";
import { Bell, Loader2 } from "lucide-react";
import { toast } from "sonner";

export default function DashboardPage() {
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [notificationPanelOpen, setNotificationPanelOpen] = useState(false);
  const [currentTab, setCurrentTab] = useState("boss");
  const [alertEndpointFilter, setAlertEndpointFilter] = useState("all");

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

  useEffect(() => {
    const timer = window.setTimeout(() => {
      const tab = new URLSearchParams(window.location.search).get("tab");
      if (tab === "system") {
        window.location.replace("/settings/status");
        return;
      }
      if (tab === "endpoints") {
        window.location.replace("/settings/endpoints?section=inventory");
        return;
      }
      if (tab === "it") {
        setCurrentTab("alerts");
        window.history.replaceState(null, "", "/?tab=alerts");
        return;
      }
      if (tab && ["boss", "alerts"].includes(tab)) {
        setCurrentTab(tab);
      }
    }, 0);
    return () => window.clearTimeout(timer);
  }, []);

  const visibleAlerts = useMemo(
    () => summary
      ? filterAlertsByEnabledCategories(summary.alerts, summary.detectionCategories)
      : [],
    [summary]
  );
  const alertEndpointOptions = useMemo(
    () => {
      const names = new Set<string>();
      visibleAlerts.forEach((alert) => {
        if (alert.agent_name) names.add(alert.agent_name);
      });
      summary?.alertTrends.forEach((trend) => {
        Object.keys(trend.endpoints || {}).forEach((endpoint) => names.add(endpoint));
      });
      return Array.from(names).sort((a, b) => a.localeCompare(b));
    },
    [summary, visibleAlerts]
  );
  const filteredAlertRecords = alertEndpointFilter === "all"
    ? visibleAlerts
    : visibleAlerts.filter((alert) => alert.agent_name === alertEndpointFilter);
  const ownerPendingCount = bossActionAlerts(visibleAlerts).length;
  const pageCopy = {
    boss: {
      title: "今日待辦",
      description: "只顯示需要老闆決定的資安事項；技術項目交給 IT",
    },
    alerts: {
      title: "告警紀錄",
      description: "供 IT 或資安顧問查證、歸檔與追蹤",
    },
  }[currentTab] || {
    title: "今日待辦",
    description: "只顯示需要老闆決定的資安事項；技術項目交給 IT",
  };

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

  return (
    <div className="flex h-full flex-col">
      {/* Page Header */}
      <header className="flex items-center justify-between border-b border-border bg-card px-6 py-4">
        <div>
          <h1 className="text-xl font-semibold">{pageCopy.title}</h1>
          <p className="text-sm text-muted-foreground">
            {pageCopy.description}
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
              {ownerPendingCount > 0 && (
                <span className="absolute -right-1 -top-1 flex size-5 items-center justify-center rounded-full bg-destructive text-xs text-destructive-foreground">
                  {ownerPendingCount}
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
        {summary && currentTab === "boss" && (
          <div className="space-y-6">
            <ExecutiveSummary
              data={summary.riskSummary}
              alerts={visibleAlerts}
              endpointCount={summary.endpoints.length}
            />
            <div className="grid gap-6 lg:grid-cols-2">
              <ActionableAlerts
                alerts={visibleAlerts}
                onStatusChange={handleStatusChange}
              />
              <DeviceStatus endpoints={summary.endpoints} />
            </div>
          </div>
        )}

        {summary && currentTab === "alerts" && (
          <div className="space-y-6">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <div className="text-sm font-medium">告警紀錄篩選</div>
                <div className="text-xs text-muted-foreground">
                  端點篩選會同時套用在趨勢線與下方告警列表。
                </div>
              </div>
              <label className="inline-flex h-9 items-center gap-2 rounded-lg border border-border bg-card px-3 text-sm font-medium">
                <span className="text-muted-foreground">端點</span>
                <select
                  value={alertEndpointFilter}
                  onChange={(event) => setAlertEndpointFilter(event.target.value)}
                  className="max-w-56 bg-transparent text-sm font-medium outline-none"
                  aria-label="告警端點篩選"
                >
                  <option value="all">全部端點</option>
                  {alertEndpointOptions.map((endpoint) => (
                    <option key={endpoint} value={endpoint}>
                      {endpoint}
                    </option>
                  ))}
                </select>
              </label>
            </div>
            <AlertTrendChart data={summary.alertTrends} selectedEndpoint={alertEndpointFilter} />
            <AlertsTable
              alerts={filteredAlertRecords}
              detectionCategories={summary.detectionCategories}
              onStatusChange={handleStatusChange}
            />
          </div>
        )}
      </main>

      <NotificationPanel
        open={notificationPanelOpen}
        onOpenChange={setNotificationPanelOpen}
        alerts={visibleAlerts}
      />
    </div>
  );
}

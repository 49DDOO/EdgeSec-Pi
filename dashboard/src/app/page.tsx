"use client";

import { Suspense, useEffect, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { DashboardPageHeader } from "@/components/dashboard/dashboard-page-header";
import {
  DashboardDataError,
  DashboardFallbackHeader,
  DashboardHomeSkeleton,
} from "@/components/dashboard/dashboard-loading-skeleton";
import { NotificationPanel } from "@/components/dashboard/notification-panel";
import { TodayDashboardView } from "@/components/dashboard/today-dashboard-view";
import { bossActionAlerts } from "@/lib/alert-routing";
import { useDashboardSummary } from "@/lib/use-dashboard-summary";

export default function DashboardPage() {
  return (
    <Suspense fallback={<DashboardFallbackHeader title="Agent 總覽" />}>
      <DashboardHomePage />
    </Suspense>
  );
}

function legacyEventsHref(searchParams: { get: (key: string) => string | null }) {
  const params = new URLSearchParams();
  ["alert", "category", "severity", "status"].forEach((key) => {
    const value = searchParams.get(key);
    if (value) params.set(key, value);
  });
  const query = params.toString();
  return query ? `/events?${query}` : "/events";
}

function DashboardHomePage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const tab = searchParams.get("tab");
  const [notificationPanelOpen, setNotificationPanelOpen] = useState(false);
  const {
    handleStatusChange,
    loadError,
    summary,
    visibleAlerts,
    isStale,
    lastUpdatedAt,
  } = useDashboardSummary();

  // 相容舊的 ?tab= 深連結：alerts/it 改走事件中心真路由，其餘舊分頁導向設定頁。
  useEffect(() => {
    if (tab === "alerts" || tab === "it") {
      router.replace(legacyEventsHref(searchParams));
    } else if (tab === "system") {
      router.replace("/settings/status");
    } else if (tab === "endpoints") {
      router.replace("/settings/endpoints?section=inventory");
    }
  }, [router, searchParams, tab]);

  const ownerPendingCount = bossActionAlerts(visibleAlerts).length;

  return (
    <div className="flex h-full flex-col">
      <DashboardPageHeader
        title="Agent Runs"
        description="先判斷認不認得；不認得就照 Agent 建議保守處理"
        ownerPendingCount={ownerPendingCount}
        onOpenNotifications={() => setNotificationPanelOpen(true)}
      />

      <main className="flex-1 overflow-auto p-6">
        {!summary && !loadError && <DashboardHomeSkeleton />}
        {loadError && <DashboardDataError message={loadError} />}
        {summary && isStale && (
          <div className="mb-4 rounded-md border border-amber-300 bg-amber-50 px-4 py-2 text-sm text-amber-800">
            與橋接服務的連線中斷，目前顯示為
            {lastUpdatedAt ? ` ${lastUpdatedAt.toLocaleTimeString("zh-TW")} ` : "稍早 "}
            的資料，將持續嘗試重新連線。
          </div>
        )}
        {summary && (
          <TodayDashboardView
            summary={summary}
            visibleAlerts={visibleAlerts}
            onStatusChange={handleStatusChange}
          />
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

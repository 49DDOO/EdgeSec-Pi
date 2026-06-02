"use client";

import { Suspense, useState } from "react";
import { useSearchParams } from "next/navigation";
import { DashboardPageHeader } from "@/components/dashboard/dashboard-page-header";
import {
  DashboardDataError,
  DashboardEventsSkeleton,
  DashboardFallbackHeader,
} from "@/components/dashboard/dashboard-loading-skeleton";
import { EventsDashboardView } from "@/components/dashboard/events-dashboard-view";
import { NotificationPanel } from "@/components/dashboard/notification-panel";
import { bossActionAlerts } from "@/lib/alert-routing";
import { useDashboardSummary } from "@/lib/use-dashboard-summary";

export default function EventsPage() {
  return (
    <Suspense fallback={<DashboardFallbackHeader title="Agent 調查紀錄" />}>
      <EventsPageContent />
    </Suspense>
  );
}

function EventsPageContent() {
  const searchParams = useSearchParams();
  const severityFilter = searchParams.get("severity") || undefined;
  const statusFilter = searchParams.get("status") || undefined;
  const categoryFilter = searchParams.get("category") || undefined;
  const [notificationPanelOpen, setNotificationPanelOpen] = useState(false);
  const {
    handleStatusChange,
    loadError,
    summary,
    visibleAlerts,
  } = useDashboardSummary();
  const ownerPendingCount = bossActionAlerts(visibleAlerts).length;

  return (
    <div className="flex h-full flex-col">
      <DashboardPageHeader
        title="Agent 調查紀錄"
        description="追蹤 Agent 已判斷、正在查證與已歸檔的跨來源安全事件"
        ownerPendingCount={ownerPendingCount}
        onOpenNotifications={() => setNotificationPanelOpen(true)}
      />

      <main className="flex-1 overflow-auto p-6">
        {!summary && !loadError && <DashboardEventsSkeleton />}
        {loadError && <DashboardDataError message={loadError} />}
        {summary && (
          <EventsDashboardView
            summary={summary}
            visibleAlerts={visibleAlerts}
            categoryFilter={categoryFilter}
            severityFilter={severityFilter}
            statusFilter={statusFilter}
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

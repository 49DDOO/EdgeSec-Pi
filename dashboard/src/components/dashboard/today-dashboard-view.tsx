"use client";

import { AgentRunsDashboard } from "@/components/dashboard/agent-runs-dashboard";
import type { DashboardSummary } from "@/lib/api";
import type { Alert, AlertStatus } from "@/lib/types";

interface TodayDashboardViewProps {
  summary: DashboardSummary;
  visibleAlerts: Alert[];
  onStatusChange: (alertId: string, newStatus: AlertStatus) => void;
}

export function TodayDashboardView({
  onStatusChange,
  summary,
  visibleAlerts,
}: TodayDashboardViewProps) {
  return (
    <AgentRunsDashboard
      summary={summary}
      visibleAlerts={visibleAlerts}
      onStatusChange={onStatusChange}
    />
  );
}

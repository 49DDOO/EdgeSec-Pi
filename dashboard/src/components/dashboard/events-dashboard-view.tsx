"use client";

import { useMemo, useState } from "react";
import { AlertTrendChart } from "@/components/dashboard/alert-trend-chart";
import { AlertsTable } from "@/components/dashboard/alerts-table";
import { TriageCommandCenter } from "@/components/dashboard/triage-command-center";
import type { DashboardSummary } from "@/lib/api";
import type { Alert, AlertStatus } from "@/lib/types";

interface EventsDashboardViewProps {
  summary: DashboardSummary;
  visibleAlerts: Alert[];
  severityFilter?: string;
  statusFilter?: string;
  categoryFilter?: string;
  onStatusChange: (alertId: string, newStatus: AlertStatus) => void;
}

export function EventsDashboardView({
  categoryFilter,
  onStatusChange,
  severityFilter,
  statusFilter,
  summary,
  visibleAlerts,
}: EventsDashboardViewProps) {
  const [alertEndpointFilter, setAlertEndpointFilter] = useState("all");
  const alertEndpointOptions = useMemo(
    () => {
      const names = new Set<string>();
      visibleAlerts.forEach((alert) => {
        if (alert.agent_name) names.add(alert.agent_name);
      });
      summary.alertTrends.forEach((trend) => {
        Object.keys(trend.endpoints || {}).forEach((endpoint) => names.add(endpoint));
      });
      return Array.from(names).sort((a, b) => a.localeCompare(b));
    },
    [summary.alertTrends, visibleAlerts]
  );
  const filteredAlertRecords = alertEndpointFilter === "all"
    ? visibleAlerts
    : visibleAlerts.filter((alert) => alert.agent_name === alertEndpointFilter);

  return (
    <div className="space-y-6">
      <TriageCommandCenter alerts={visibleAlerts} />
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="text-sm font-medium">事件中心篩選</div>
          <div className="text-xs text-muted-foreground">
            端點篩選會同時套用在趨勢線與下方事件列表。
          </div>
        </div>
        <label className="inline-flex h-9 items-center gap-2 rounded-lg border border-border bg-card px-3 text-sm font-medium">
          <span className="text-muted-foreground">端點</span>
          <select
            value={alertEndpointFilter}
            onChange={(event) => setAlertEndpointFilter(event.target.value)}
            className="max-w-56 bg-transparent text-sm font-medium text-foreground outline-none"
            aria-label="事件端點篩選"
          >
            <option value="all" className="bg-card text-foreground">全部端點</option>
            {alertEndpointOptions.map((endpoint) => (
              <option key={endpoint} value={endpoint} className="bg-card text-foreground">
                {endpoint}
              </option>
            ))}
          </select>
        </label>
      </div>
      <AlertTrendChart data={summary.alertTrends} selectedEndpoint={alertEndpointFilter} />
      <AlertsTable
        key={`${statusFilter || "all"}:${severityFilter || "all"}:${categoryFilter || "all"}`}
        alerts={filteredAlertRecords}
        detectionCategories={summary.detectionCategories}
        initialCategoryFilter={categoryFilter}
        initialSeverityFilter={severityFilter}
        initialStatusFilter={statusFilter}
        onStatusChange={onStatusChange}
      />
    </div>
  );
}

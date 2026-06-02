"use client";

import { useMemo, useState } from "react";
import { AlertDetailDialog } from "@/components/dashboard/alerts/alert-detail-dialog";
import { AlertsRecordsCard } from "@/components/dashboard/alerts/alert-records-card";
import {
  groupAlerts,
  statusLabelForRecord,
  type AlertDetailView,
} from "@/components/dashboard/alerts/alert-table-model";
import { sendAlertInvestigationMessage } from "@/lib/api";
import {
  categoryForAlert,
  normalizedDetectionSettings,
} from "@/lib/detection-categories";
import { relatedIp } from "@/lib/investigation";
import type {
  Alert,
  AlertStatus,
  DetectionCategoryKey,
  DetectionCategorySettings,
  SeverityLevel,
} from "@/lib/types";
import { useInvestigationSessions } from "@/lib/use-investigation-sessions";
import { toast } from "sonner";

interface AlertsTableProps {
  alerts: Alert[];
  onStatusChange?: (alertId: string, newStatus: AlertStatus) => void;
  detectionCategories?: DetectionCategorySettings;
  initialCategoryFilter?: string;
  initialSeverityFilter?: string;
  initialStatusFilter?: string;
}

type SeverityFilter = SeverityLevel | "urgent" | "all";

const severityFilters = new Set(["all", "urgent", "critical", "high", "medium", "low"]);
const statusFilters = new Set(["all", "pending", "acknowledged", "resolved", "false_positive"]);

function normalizeSeverityFilter(value?: string): SeverityFilter {
  return severityFilters.has(value || "") ? value as SeverityFilter : "all";
}

function normalizeStatusFilter(value?: string): AlertStatus | "all" {
  return statusFilters.has(value || "") ? value as AlertStatus | "all" : "all";
}

export function AlertsTable({
  alerts,
  onStatusChange,
  detectionCategories,
  initialCategoryFilter,
  initialSeverityFilter,
  initialStatusFilter,
}: AlertsTableProps) {
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(() => {
    if (typeof window === "undefined") return null;
    return new URLSearchParams(window.location.search).get("alert");
  });
  const [detailView, setDetailView] = useState<AlertDetailView>("details");
  const [filterSeverity, setFilterSeverity] = useState<SeverityFilter>(() => (
    normalizeSeverityFilter(initialSeverityFilter)
  ));
  const [filterStatus, setFilterStatus] = useState<AlertStatus | "all">(() => (
    normalizeStatusFilter(initialStatusFilter)
  ));
  const [filterCategory, setFilterCategory] = useState<DetectionCategoryKey | "all">(
    () => initialCategoryFilter as DetectionCategoryKey || "all"
  );
  const [investigationLoading, setInvestigationLoading] = useState(false);
  const { getSession, saveSession } = useInvestigationSessions();

  const selectedAlert = selectedAlertId ? alerts.find((alert) => alert.id === selectedAlertId) || null : null;
  const categorySettings = useMemo(
    () => normalizedDetectionSettings(detectionCategories),
    [detectionCategories]
  );

  const enabledCategoryKeys = categorySettings.categories
    .filter((category) => categorySettings.enabled[category.key])
    .map((category) => category.key);

  const baseFilteredAlerts = alerts.filter((alert) => {
    const category = categoryForAlert(alert);
    if (!categorySettings.enabled[category]) return false;
    if (filterSeverity === "urgent" && alert.severity !== "critical" && alert.severity !== "high") return false;
    if (filterSeverity !== "all" && filterSeverity !== "urgent" && alert.severity !== filterSeverity) return false;
    if (filterStatus !== "all" && alert.status !== filterStatus) return false;
    return true;
  });
  const filteredAlerts = baseFilteredAlerts.filter((alert) => (
    filterCategory === "all" || categoryForAlert(alert) === filterCategory
  ));
  const groupedAlerts = groupAlerts(filteredAlerts);
  const categoryCounts = Object.fromEntries(
    categorySettings.categories.map((category) => [category.key, 0])
  ) as Record<DetectionCategoryKey, number>;
  for (const alert of baseFilteredAlerts) {
    const category = categoryForAlert(alert);
    if (categorySettings.enabled[category]) {
      categoryCounts[category] = (categoryCounts[category] || 0) + 1;
    }
  }

  const handleStatusChange = (alertId: string, newStatus: AlertStatus) => {
    onStatusChange?.(alertId, newStatus);
    toast.success(`事件狀態已更新為「${statusLabelForRecord(newStatus)}」`);
  };

  const handleGroupStatusChange = (items: Alert[], newStatus: AlertStatus) => {
    items.forEach((item) => handleStatusChange(item.id, newStatus));
  };

  const openInvestigation = (alert: Alert) => {
    setSelectedAlertId(alert.id);
    setDetailView("mcp");
  };

  const closeSelectedAlert = () => {
    setSelectedAlertId(null);
    setDetailView("details");
    const url = new URL(window.location.href);
    if (url.searchParams.has("alert")) {
      url.searchParams.delete("alert");
      window.history.replaceState(null, "", `${url.pathname}${url.search}`);
    }
  };

  const runInvestigation = async (question: string) => {
    if (!selectedAlert || investigationLoading) return;
    const sessionKey = `alert:${selectedAlert.id}`;
    const currentSession = getSession(sessionKey);
    const nextMessages = [
      ...currentSession.messages,
      { role: "user" as const, content: question },
    ];
    saveSession(sessionKey, { messages: nextMessages, evidence: [], suggestions: [] });
    setInvestigationLoading(true);
    try {
      const response = await sendAlertInvestigationMessage({
        alertId: selectedAlert.id,
        question,
        messages: currentSession.messages,
      });
      saveSession(sessionKey, {
        messages: [
          ...nextMessages,
          { role: "assistant", content: response.answer_zh },
        ],
        evidence: response.evidence || [],
        suggestions: response.suggestions || [],
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      saveSession(sessionKey, {
        messages: [
          ...nextMessages,
          { role: "assistant", content: `調查失敗：${message}` },
        ],
        evidence: [],
        suggestions: [],
      });
      toast.error("調查失敗", { description: message });
    } finally {
      setInvestigationLoading(false);
    }
  };

  const investigationSession = getSession(selectedAlert ? `alert:${selectedAlert.id}` : "");
  const selectedRelatedIp = selectedAlert ? relatedIp(selectedAlert) : "";
  const prioritizeHandoff = Boolean(
    selectedAlert
      && selectedAlert.status === "pending"
      && ["critical", "high"].includes(selectedAlert.severity)
  );

  return (
    <>
      <AlertsRecordsCard
        baseFilteredCount={baseFilteredAlerts.length}
        categoryCounts={categoryCounts}
        categorySettings={categorySettings}
        enabledCategoryKeys={enabledCategoryKeys}
        expandedId={expandedId}
        filterCategory={filterCategory}
        filterSeverity={filterSeverity}
        filterStatus={filterStatus}
        filteredCount={filteredAlerts.length}
        groupedAlerts={groupedAlerts}
        pendingCount={filteredAlerts.filter((alert) => alert.status === "pending").length}
        onExpandedChange={setExpandedId}
        onFilterCategoryChange={setFilterCategory}
        onFilterSeverityChange={setFilterSeverity}
        onFilterStatusChange={setFilterStatus}
        onGroupStatusChange={handleGroupStatusChange}
        onOpenInvestigation={openInvestigation}
        onSelectAlert={(alert) => setSelectedAlertId(alert.id)}
      />

      <AlertDetailDialog
        alert={selectedAlert}
        detailView={detailView}
        investigationLoading={investigationLoading}
        investigationSession={investigationSession}
        prioritizeHandoff={prioritizeHandoff}
        relatedIp={selectedRelatedIp}
        onClose={closeSelectedAlert}
        onDetailViewChange={setDetailView}
        onRunInvestigation={(question) => void runInvestigation(question)}
        onStatusChange={handleStatusChange}
      />
    </>
  );
}

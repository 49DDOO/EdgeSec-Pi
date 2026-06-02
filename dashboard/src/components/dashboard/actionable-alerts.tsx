"use client";

import { useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
} from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { isBossActionAlert, itFollowupAlerts } from "@/lib/alert-routing";
import { sendAlertInvestigationMessage } from "@/lib/api";
import { hasMultipleSources } from "@/lib/source-labels";
import type { Alert, AlertStatus } from "@/lib/types";
import { useInvestigationSessions } from "@/lib/use-investigation-sessions";
import { toast } from "sonner";
import { ActionableAlertCard } from "./actionable-alerts/actionable-alert-card";
import { groupPendingAlerts } from "./actionable-alerts/actionable-alert-helpers";
import { ActionableInvestigationSheet } from "./actionable-alerts/actionable-investigation-sheet";
import type { ActionableAlertGroup } from "./actionable-alerts/actionable-alert-types";

interface ActionableAlertsProps {
  alerts: Alert[];
  onStatusChange?: (alertId: string, newStatus: AlertStatus) => void;
}

export function ActionableAlerts({ alerts, onStatusChange }: ActionableAlertsProps) {
  const bossAlerts = alerts.filter(isBossActionAlert);
  const itAlerts = itFollowupAlerts(alerts);
  const alertGroups = groupPendingAlerts(bossAlerts);
  const hasMultipleSourceContext = hasMultipleSources(alerts.map((alert) => alert.siem_source));
  const [investigatingGroup, setInvestigatingGroup] = useState<ActionableAlertGroup | null>(null);
  const [investigationLoading, setInvestigationLoading] = useState(false);
  const { getSession, saveSession } = useInvestigationSessions();
  
  const handleAction = (group: ActionableAlertGroup, action: "it" | "ok" | "false") => {
    const statusMap: Record<string, AlertStatus> = {
      it: "acknowledged",
      ok: "resolved",
      false: "false_positive",
    };
    const labelMap: Record<string, string> = {
      it: "已轉交 IT 處理",
      ok: "已標記為正常",
      false: "已標記為誤報",
    };
    group.alerts.forEach((alert) => onStatusChange?.(alert.id, statusMap[action]));
    toast.success(labelMap[action], {
      description: group.alerts.length > 1 ? `已套用到 ${group.alerts.length} 筆同類事件` : undefined,
    });
  };

  const openInvestigation = (group: ActionableAlertGroup) => {
    setInvestigatingGroup(group);
  };

  const runInvestigation = async (question: string) => {
    if (!investigatingGroup || investigationLoading) return;
    const alert = investigatingGroup.primary;
    const sessionKey = `today:${investigatingGroup.key}`;
    const currentSession = getSession(sessionKey);
    const nextMessages = [
      ...currentSession.messages,
      { role: "user" as const, content: question },
    ];
    saveSession(sessionKey, { messages: nextMessages, evidence: [] });
    setInvestigationLoading(true);
    try {
      const response = await sendAlertInvestigationMessage({
        alertId: alert.id,
        question,
        messages: currentSession.messages,
      });
      saveSession(sessionKey, {
        messages: [
          ...nextMessages,
          { role: "assistant", content: response.answer_zh },
        ],
        evidence: response.evidence || [],
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      saveSession(sessionKey, {
        messages: [
          ...nextMessages,
          { role: "assistant", content: `調查失敗：${message}` },
        ],
        evidence: [],
      });
      toast.error("調查失敗", { description: message });
    } finally {
      setInvestigationLoading(false);
    }
  };

  if (alertGroups.length === 0) {
    return (
      <Card>
        <CardContent className="flex flex-col items-center justify-center py-12 text-center">
          <CheckCircle2 className="mb-4 size-16 text-success" />
          <h3 className="text-xl font-semibold">沒有待處理事項</h3>
          <p className="mt-2 text-muted-foreground">
            目前沒有 Agent 需要你決定的資安事項
          </p>
          {itAlerts.length > 0 && (
            <p className="mt-3 rounded-lg bg-muted px-3 py-2 text-sm text-muted-foreground">
              IT 仍有 {itAlerts.length} 件技術項目待確認，已放在調查紀錄裡。
            </p>
          )}
        </CardContent>
      </Card>
    );
  }

  const investigationSessionKey = investigatingGroup ? `today:${investigatingGroup.key}` : "";
  const investigationSession = getSession(investigationSessionKey);

  return (
    <>
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <AlertTriangle className="size-5 text-high" />
          Agent 請示事項
        </CardTitle>
        <CardDescription>
          只列 Agent 需要你批准、判斷或交給 IT 的事件；技術噪音已移到調查紀錄
          {alertGroups.some((group) => group.alerts.length > 1)
            ? "。同一台端點的同類事件已合併顯示"
            : ""}
          {itAlerts.length > 0 ? `。另有 ${itAlerts.length} 件 IT 待確認項目` : ""}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {alertGroups.map((group, index) => (
          <ActionableAlertCard
            key={group.key}
            group={group}
            hasMultipleSourceContext={hasMultipleSourceContext}
            index={index}
            onAction={handleAction}
            onOpenInvestigation={openInvestigation}
          />
        ))}
      </CardContent>
    </Card>
    <ActionableInvestigationSheet
      group={investigatingGroup}
      investigationLoading={investigationLoading}
      investigationSession={investigationSession}
      onAction={handleAction}
      onOpenChange={(open) => {
        if (!open) setInvestigatingGroup(null);
      }}
      onRunInvestigation={runInvestigation}
    />
    </>
  );
}

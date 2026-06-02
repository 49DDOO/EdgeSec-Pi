"use client";

import {
  AlertTriangle,
  Search,
  ShieldAlert,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { firstIpLike } from "@/lib/investigation";
import { shouldShowSourceBadge, sourceLabel } from "@/lib/source-labels";
import {
  formatGroupTimeRange,
  getDecisionQuestion,
  getPlainBusinessImpact,
  getPlainLanguageTitle,
  isDocumentationIp,
  splitActionLines,
} from "./actionable-alert-helpers";
import { ActionableAlertActions } from "./actionable-alert-actions";
import type { ActionableAlertGroup } from "./actionable-alert-types";

interface ActionableAlertCardProps {
  group: ActionableAlertGroup;
  hasMultipleSourceContext: boolean;
  index: number;
  onAction: (group: ActionableAlertGroup, action: "it" | "ok" | "false") => void;
  onOpenInvestigation: (group: ActionableAlertGroup) => void;
}

export function ActionableAlertCard({
  group,
  hasMultipleSourceContext,
  index,
  onAction,
  onOpenInvestigation,
}: ActionableAlertCardProps) {
  const alert = group.primary;
  const groupedCount = group.alerts.length;
  const sourceIp = firstIpLike(alert);
  const isTestLike = Boolean(alert.sampledata || isDocumentationIp(sourceIp));

  return (
    <div>
      {index > 0 && <Separator className="my-4" />}
      <div className="space-y-3">
        {/* 標題和嚴重程度 */}
        <div className="flex flex-wrap items-start justify-between gap-2">
          <div className="flex items-center gap-2">
            {alert.severity === "critical" ? (
              <ShieldAlert className="size-5 text-critical" />
            ) : (
              <AlertTriangle className="size-5 text-high" />
            )}
            <span className="font-semibold">{getPlainLanguageTitle(alert)}</span>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            {shouldShowSourceBadge(alert.siem_source, hasMultipleSourceContext) && (
              <Badge variant="outline">{sourceLabel(alert.siem_source)}</Badge>
            )}
            {groupedCount > 1 && (
              <Badge variant="outline">同類 {groupedCount} 筆</Badge>
            )}
            {isTestLike && (
              <Badge variant="outline" className="border-blue-300 bg-blue-50 text-blue-700 dark:border-blue-900 dark:bg-blue-950/30 dark:text-blue-200">
                {alert.sampledata ? "測試資料" : "測試/文件 IP"}
              </Badge>
            )}
            <Badge
              variant={alert.severity === "critical" ? "destructive" : "secondary"}
            >
              {alert.severity === "critical" ? "緊急" : "重要"}
            </Badge>
          </div>
        </div>

        {/* 一句話說明影響 */}
        <div className="rounded-lg bg-muted/50 p-3">
          <p className="text-sm">
            <span className="font-medium">影響：</span>
            {getPlainBusinessImpact(alert)}
          </p>
          <p className="mt-2 text-sm">
            <span className="font-medium">現在要確認：</span>
            {getDecisionQuestion(alert)}
          </p>
          <p className="mt-2 text-xs text-muted-foreground">
            端點：{alert.agent_name}
            {alert.purpose ? ` / 用途：${alert.purpose}` : ""}
            {sourceIp ? ` / 來源 IP：${sourceIp}` : ""}
          </p>
          {isDocumentationIp(sourceIp) && (
            <p className="mt-1 text-xs text-blue-700 dark:text-blue-200">
              此來源 IP 屬於文件保留網段，通常代表測試或範例資料，不是真實外部攻擊來源。
            </p>
          )}
          {groupedCount > 1 && (
            <p className="mt-1 text-xs text-muted-foreground">
              發生次數：{groupedCount} 次 / 時間：{formatGroupTimeRange(group.alerts)}
            </p>
          )}
        </div>

        {alert.investigation_summary_zh && (
          <div className="rounded-lg border border-primary/20 bg-primary/5 p-3">
            <div className="flex items-center gap-1.5 text-xs font-medium text-primary">
              <Search className="size-3.5" />
              AI 調查說明
            </div>
            <p className="mt-1.5 text-sm leading-6">{alert.investigation_summary_zh}</p>
          </div>
        )}

        {splitActionLines(alert.recommended_action).length > 0 && (
          <div className="border-l-2 border-border pl-3">
            <div className="text-xs font-medium text-muted-foreground">建議處理順序</div>
            <ol className="mt-2 list-decimal space-y-1 pl-5 text-sm">
              {splitActionLines(alert.recommended_action).slice(0, 4).map((line) => (
                <li key={line}>{line}</li>
              ))}
            </ol>
          </div>
        )}

        <ActionableAlertActions
          group={group}
          onAction={onAction}
          onOpenInvestigation={onOpenInvestigation}
        />
        {groupedCount > 1 && (
          <div className="text-xs text-muted-foreground">
            這張卡合併了 {groupedCount} 筆同類事件。按處理按鈕時，會一起更新這些事件的狀態。
          </div>
        )}
      </div>
    </div>
  );
}

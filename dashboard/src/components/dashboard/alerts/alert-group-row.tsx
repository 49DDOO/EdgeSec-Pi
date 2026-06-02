"use client";

import {
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Search,
  Server,
  XCircle,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  TableCell,
  TableRow,
} from "@/components/ui/table";
import { TechnicalAlertDetails } from "@/components/dashboard/technical-alert-details";
import {
  categoryForAlert,
  categoryLabel,
} from "@/lib/detection-categories";
import type {
  Alert,
  AlertStatus,
  DetectionCategorySettings,
} from "@/lib/types";
import { severityLabels } from "@/lib/labels";
import {
  formatGroupTimeRange,
  getSeverityBadgeClass,
  getSeverityIcon,
  getStatusBadgeClass,
  statusLabelForRecord,
  type AlertRecordGroup,
} from "./alert-table-model";
import { shouldShowSourceBadge, sourceLabel } from "@/lib/source-labels";

interface AlertGroupRowProps {
  group: AlertRecordGroup;
  expanded: boolean;
  categorySettings: DetectionCategorySettings;
  showSourceColumn: boolean;
  hasMultipleSourceContext: boolean;
  onExpandedChange: (groupKey: string | null) => void;
  onSelectAlert: (alert: Alert) => void;
  onOpenInvestigation: (alert: Alert) => void;
  onGroupStatusChange: (alerts: Alert[], status: AlertStatus) => void;
}

export function AlertGroupRow({
  categorySettings,
  expanded,
  group,
  hasMultipleSourceContext,
  onExpandedChange,
  onGroupStatusChange,
  onOpenInvestigation,
  onSelectAlert,
  showSourceColumn,
}: AlertGroupRowProps) {
  const alert = group.primary;
  const showSourceBadge = shouldShowSourceBadge(alert.siem_source, hasMultipleSourceContext);
  return (
    <>
      <TableRow
        className="cursor-pointer hover:bg-muted/50"
        onClick={() => onSelectAlert(alert)}
      >
        <TableCell>
          <Badge className={getSeverityBadgeClass(alert.severity)}>
            {getSeverityIcon(alert.severity)}
            <span className="ml-1">{severityLabels[alert.severity]}</span>
          </Badge>
        </TableCell>
        <TableCell>
          <div className="font-medium">{alert.summary || alert.rule_description}</div>
          <div className="line-clamp-1 text-sm text-muted-foreground">
            {categoryLabel(categoryForAlert(alert), categorySettings.categories)} · {alert.business_impact}
          </div>
          {group.alerts.length > 1 && (
            <div className="mt-1 text-xs text-muted-foreground">
              同類事件 {group.alerts.length} 次
            </div>
          )}
        </TableCell>
        {showSourceColumn && (
          <TableCell className="hidden xl:table-cell">
            {showSourceBadge && <Badge variant="outline">{sourceLabel(alert.siem_source)}</Badge>}
          </TableCell>
        )}
        <TableCell className="hidden md:table-cell">
          <div className="flex items-center gap-2">
            <Server className="size-4 text-muted-foreground" />
            <span>{alert.agent_name}</span>
          </div>
        </TableCell>
        <TableCell className="hidden text-muted-foreground lg:table-cell">
          {formatGroupTimeRange(group.alerts)}
        </TableCell>
        <TableCell>
          <Badge variant="outline" className={getStatusBadgeClass(alert.status)}>
            {statusLabelForRecord(alert.status)}
          </Badge>
        </TableCell>
        <TableCell>
          <Button
            variant="ghost"
            size="icon"
            className="size-8"
            onClick={(event) => {
              event.stopPropagation();
              onExpandedChange(expanded ? null : group.key);
            }}
          >
            {expanded ? <ChevronUp className="size-4" /> : <ChevronDown className="size-4" />}
          </Button>
        </TableCell>
      </TableRow>
      {expanded && (
        <TableRow key={`${group.key}-expanded`}>
          <TableCell colSpan={showSourceColumn ? 7 : 6} className="bg-muted/30 p-4">
            {group.alerts.length > 1 && (
              <div className="mb-4 rounded-md border bg-background p-3 text-sm">
                <div className="font-medium">同類事件已合併</div>
                <div className="mt-1 text-muted-foreground">
                  共 {group.alerts.length} 次，時間：{formatGroupTimeRange(group.alerts)}
                </div>
              </div>
            )}
            <div className="grid gap-4 md:grid-cols-2">
              <div>
                <h4 className="mb-2 font-semibold">業務影響</h4>
                <p className="text-sm text-muted-foreground">
                  {alert.business_impact}
                </p>
              </div>
              <div>
                <h4 className="mb-2 font-semibold">建議處理步驟</h4>
                <p className="whitespace-pre-line text-sm text-muted-foreground">
                  {alert.recommended_action}
                </p>
              </div>
            </div>
            <div className="mt-4">
              <TechnicalAlertDetails alert={alert} compact />
            </div>
            <div className="mt-4 flex flex-wrap gap-2">
              <Button
                type="button"
                variant="secondary"
                size="sm"
                onClick={(event) => {
                  event.stopPropagation();
                  onOpenInvestigation(alert);
                }}
              >
                <Search data-icon="inline-start" />
                查證證據
              </Button>
              <Button
                size="sm"
                variant="outline"
                onClick={() => onGroupStatusChange(group.alerts, "acknowledged")}
              >
                <CheckCircle2 data-icon="inline-start" />
                正常操作
              </Button>
              <Button
                size="sm"
                variant="outline"
                onClick={() => onGroupStatusChange(group.alerts, "resolved")}
              >
                <CheckCircle2 data-icon="inline-start" />
                已處理
              </Button>
              <Button
                size="sm"
                variant="outline"
                onClick={() => onGroupStatusChange(group.alerts, "false_positive")}
              >
                <XCircle data-icon="inline-start" />
                誤報
              </Button>
            </div>
          </TableCell>
        </TableRow>
      )}
    </>
  );
}

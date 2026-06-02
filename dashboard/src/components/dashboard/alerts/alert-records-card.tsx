"use client";

import { Filter } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Table,
  TableBody,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import type {
  Alert,
  AlertStatus,
  DetectionCategoryKey,
  DetectionCategorySettings,
  SeverityLevel,
} from "@/lib/types";
import { hasMultipleSources, shouldShowSourceBadge } from "@/lib/source-labels";
import { AlertGroupRow } from "./alert-group-row";
import type { AlertRecordGroup } from "./alert-table-model";

interface AlertsRecordsCardProps {
  groupedAlerts: AlertRecordGroup[];
  filteredCount: number;
  pendingCount: number;
  baseFilteredCount: number;
  categoryCounts: Record<DetectionCategoryKey, number>;
  categorySettings: DetectionCategorySettings;
  enabledCategoryKeys: DetectionCategoryKey[];
  expandedId: string | null;
  filterCategory: DetectionCategoryKey | "all";
  filterSeverity: SeverityLevel | "urgent" | "all";
  filterStatus: AlertStatus | "all";
  onExpandedChange: (groupKey: string | null) => void;
  onFilterSeverityChange: (value: SeverityLevel | "urgent" | "all") => void;
  onFilterStatusChange: (value: AlertStatus | "all") => void;
  onFilterCategoryChange: (value: DetectionCategoryKey | "all") => void;
  onSelectAlert: (alert: Alert) => void;
  onOpenInvestigation: (alert: Alert) => void;
  onGroupStatusChange: (alerts: Alert[], status: AlertStatus) => void;
}

export function AlertsRecordsCard({
  groupedAlerts,
  filteredCount,
  pendingCount,
  baseFilteredCount,
  categoryCounts,
  categorySettings,
  enabledCategoryKeys,
  expandedId,
  filterCategory,
  filterSeverity,
  filterStatus,
  onExpandedChange,
  onFilterCategoryChange,
  onFilterSeverityChange,
  onFilterStatusChange,
  onGroupStatusChange,
  onOpenInvestigation,
  onSelectAlert,
}: AlertsRecordsCardProps) {
  const severityLabel = filterSeverity === "all"
    ? "嚴重程度"
    : filterSeverity === "urgent"
      ? "高風險"
      : ({ critical: "危急", high: "高", medium: "中", low: "低" } as Record<SeverityLevel, string>)[filterSeverity];
  const statusLabel = filterStatus === "all"
    ? "狀態"
    : filterStatus === "pending"
      ? "IT 待確認"
      : filterStatus === "acknowledged"
        ? "已確認"
        : filterStatus === "resolved"
          ? "已解決"
          : "誤報";
  const hasMultipleSourceContext = hasMultipleSources(
    groupedAlerts.flatMap((group) => group.alerts.map((alert) => alert.siem_source))
  );
  const showSourceColumn = groupedAlerts.some((group) => (
    shouldShowSourceBadge(group.primary.siem_source, hasMultipleSourceContext)
  ));

  return (
    <Card>
      <CardHeader>
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <CardTitle>事件中心</CardTitle>
            <CardDescription>
              共 {filteredCount} 筆事件，已合併為 {groupedAlerts.length} 組供 IT 或資安顧問查證
              {pendingCount > 0 && (
                <span className="ml-1 text-muted-foreground">
                  ({pendingCount} 筆尚未歸檔)
                </span>
              )}
            </CardDescription>
          </div>
          <div className="flex flex-wrap gap-2">
            <DropdownMenu>
              <DropdownMenuTrigger render={<Button variant="outline" size="sm" />}>
                <Filter data-icon="inline-start" />
                {severityLabel}
              </DropdownMenuTrigger>
              <DropdownMenuContent>
                <DropdownMenuGroup>
                  <DropdownMenuItem onClick={() => onFilterSeverityChange("all")}>
                    全部
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={() => onFilterSeverityChange("urgent")}>
                    高風險
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={() => onFilterSeverityChange("critical")}>
                    危急
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={() => onFilterSeverityChange("high")}>
                    高
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={() => onFilterSeverityChange("medium")}>
                    中
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={() => onFilterSeverityChange("low")}>
                    低
                  </DropdownMenuItem>
                </DropdownMenuGroup>
              </DropdownMenuContent>
            </DropdownMenu>
            <DropdownMenu>
              <DropdownMenuTrigger render={<Button variant="outline" size="sm" />}>
                <Filter data-icon="inline-start" />
                {statusLabel}
              </DropdownMenuTrigger>
              <DropdownMenuContent>
                <DropdownMenuGroup>
                  <DropdownMenuItem onClick={() => onFilterStatusChange("all")}>
                    全部
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={() => onFilterStatusChange("pending")}>
                    IT 待確認
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={() => onFilterStatusChange("acknowledged")}>
                    已確認
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={() => onFilterStatusChange("resolved")}>
                    已解決
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={() => onFilterStatusChange("false_positive")}>
                    誤報
                  </DropdownMenuItem>
                </DropdownMenuGroup>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <div className="mb-4 flex flex-wrap gap-2">
          <Button
            type="button"
            variant={filterCategory === "all" ? "default" : "outline"}
            size="sm"
            onClick={() => onFilterCategoryChange("all")}
          >
            全部
            <span className="ml-1 text-xs opacity-75">{baseFilteredCount}</span>
          </Button>
          {categorySettings.categories
            .filter((category) => categorySettings.enabled[category.key])
            .map((category) => (
              <Button
                key={category.key}
                type="button"
                variant={filterCategory === category.key ? "default" : "outline"}
                size="sm"
                onClick={() => onFilterCategoryChange(category.key)}
              >
                {category.label_zh}
                <span className="ml-1 text-xs opacity-75">{categoryCounts[category.key] || 0}</span>
              </Button>
            ))}
          {!enabledCategoryKeys.length && (
            <p className="text-sm text-muted-foreground">
              尚未啟用任何 Wazuh 訊號類別，請至「事件來源 / Wazuh 訊號類別」設定開啟至少一項。
            </p>
          )}
        </div>
        <ScrollArea className="h-[calc(100vh-22rem)] min-h-[520px]">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-[100px]">嚴重程度</TableHead>
                <TableHead>描述</TableHead>
                {showSourceColumn && (
                  <TableHead className="hidden xl:table-cell">來源</TableHead>
                )}
                <TableHead className="hidden md:table-cell">端點</TableHead>
                <TableHead className="hidden lg:table-cell">時間</TableHead>
                <TableHead>狀態</TableHead>
                <TableHead className="w-[50px]"></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {groupedAlerts.map((group) => (
                <AlertGroupRow
                  key={group.key}
                  expanded={expandedId === group.key}
                  group={group}
                  showSourceColumn={showSourceColumn}
                  hasMultipleSourceContext={hasMultipleSourceContext}
                  onExpandedChange={onExpandedChange}
                  onGroupStatusChange={onGroupStatusChange}
                  onOpenInvestigation={onOpenInvestigation}
                  onSelectAlert={onSelectAlert}
                  categorySettings={categorySettings}
                />
              ))}
            </TableBody>
          </Table>
        </ScrollArea>
      </CardContent>
    </Card>
  );
}

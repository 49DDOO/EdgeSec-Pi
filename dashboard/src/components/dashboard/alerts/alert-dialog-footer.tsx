"use client";

import { CheckCircle2, XCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import type { Alert, AlertStatus } from "@/lib/types";
import {
  neutralButtonClass,
  selectedNeutralButtonClass,
  type AlertDetailView,
} from "./alert-table-model";

interface AlertDialogFooterProps {
  alert: Alert;
  detailView: AlertDetailView;
  prioritizeHandoff: boolean;
  onDetailViewChange: (view: AlertDetailView) => void;
  onStatusChange: (alertId: string, status: AlertStatus) => void;
}

export function AlertDialogFooter({
  alert,
  detailView,
  prioritizeHandoff,
  onDetailViewChange,
  onStatusChange,
}: AlertDialogFooterProps) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 border-t bg-card px-6 py-4">
      <div className="flex flex-wrap gap-2">
        {detailView === "mcp" && (
          <Button
            type="button"
            variant="outline"
            className={neutralButtonClass}
            onClick={() => onDetailViewChange("details")}
          >
            回到事件內容
          </Button>
        )}
        {detailView === "mcp" ? (
          <Button
            variant="outline"
            className={selectedNeutralButtonClass}
            onClick={() => onStatusChange(alert.id, "acknowledged")}
          >
            <CheckCircle2 data-icon="inline-start" />
            交給 IT 處理
          </Button>
        ) : prioritizeHandoff ? (
          <Button
            variant="outline"
            className={selectedNeutralButtonClass}
            onClick={() => onStatusChange(alert.id, "acknowledged")}
          >
            <CheckCircle2 data-icon="inline-start" />
            交給 IT 處理
          </Button>
        ) : (
          <Button
            variant="outline"
            className={selectedNeutralButtonClass}
            onClick={() => onStatusChange(alert.id, "acknowledged")}
          >
            <CheckCircle2 data-icon="inline-start" />
            正常操作
          </Button>
        )}
        {detailView === "details" && prioritizeHandoff && (
          <Button
            variant="outline"
            className={neutralButtonClass}
            onClick={() => onStatusChange(alert.id, "acknowledged")}
          >
            <CheckCircle2 data-icon="inline-start" />
            正常操作
          </Button>
        )}
        {detailView === "mcp" && (
          <Button
            variant="outline"
            className={neutralButtonClass}
            onClick={() => onStatusChange(alert.id, "acknowledged")}
          >
            <CheckCircle2 data-icon="inline-start" />
            正常操作
          </Button>
        )}
        <Button
          variant="outline"
          className={neutralButtonClass}
          onClick={() => onStatusChange(alert.id, "resolved")}
        >
          <CheckCircle2 data-icon="inline-start" />
          已處理
        </Button>
        <Button
          variant="outline"
          className={neutralButtonClass}
          onClick={() => onStatusChange(alert.id, "false_positive")}
        >
          <XCircle data-icon="inline-start" />
          誤報
        </Button>
      </div>
    </div>
  );
}

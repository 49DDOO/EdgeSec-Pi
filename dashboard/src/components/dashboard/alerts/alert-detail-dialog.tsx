"use client";

import { Search } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { ScrollArea } from "@/components/ui/scroll-area";
import type { Alert, AlertStatus } from "@/lib/types";
import type { InvestigationSession } from "@/lib/use-investigation-sessions";
import { severityLabels } from "@/lib/labels";
import { AlertDetailsPanel } from "./alert-details-panel";
import { AlertDialogFooter } from "./alert-dialog-footer";
import { AlertInvestigationPanel } from "./alert-investigation-panel";
import {
  getSeverityBadgeClass,
  getSeverityIcon,
  getStatusBadgeClass,
  modalTabClass,
  statusLabelForRecord,
  type AlertDetailView,
} from "./alert-table-model";

interface AlertDetailDialogProps {
  alert: Alert | null;
  detailView: AlertDetailView;
  investigationLoading: boolean;
  investigationSession: InvestigationSession;
  prioritizeHandoff: boolean;
  relatedIp: string;
  onClose: () => void;
  onDetailViewChange: (view: AlertDetailView) => void;
  onRunInvestigation: (question: string) => void;
  onStatusChange: (alertId: string, status: AlertStatus) => void;
}

export function AlertDetailDialog({
  alert,
  detailView,
  investigationLoading,
  investigationSession,
  prioritizeHandoff,
  relatedIp,
  onClose,
  onDetailViewChange,
  onRunInvestigation,
  onStatusChange,
}: AlertDetailDialogProps) {
  return (
    <Dialog
      open={!!alert}
      onOpenChange={(open) => {
        if (open) return;
        onClose();
      }}
    >
      <DialogContent className="max-h-[90vh] w-[min(1280px,calc(100vw-2rem))] overflow-hidden p-0 sm:max-w-[min(1280px,calc(100vw-2rem))]">
        <DialogHeader className="px-6 pt-6">
          <DialogTitle className="flex items-center gap-2 pr-12 text-lg">
            {alert && getSeverityIcon(alert.severity)}
            {alert?.summary || alert?.rule_description}
          </DialogTitle>
          <DialogDescription>
            規則 ID: {alert?.rule_id}
            {alert?.rule_description ? ` / ${alert.rule_description}` : ""}
          </DialogDescription>
        </DialogHeader>
        {alert && (
          <div className="flex min-h-0 flex-1 flex-col">
            <DialogTabs
              alert={alert}
              detailView={detailView}
              onDetailViewChange={onDetailViewChange}
            />

            <ScrollArea className="max-h-[calc(90vh-12rem)] px-6 py-5">
              {detailView === "details" ? (
                <AlertDetailsPanel alert={alert} relatedIp={relatedIp} />
              ) : (
                <AlertInvestigationPanel
                  alert={alert}
                  investigationLoading={investigationLoading}
                  investigationSession={investigationSession}
                  relatedIp={relatedIp}
                  onRunInvestigation={onRunInvestigation}
                />
              )}
            </ScrollArea>

            <AlertDialogFooter
              alert={alert}
              detailView={detailView}
              prioritizeHandoff={prioritizeHandoff}
              onDetailViewChange={onDetailViewChange}
              onStatusChange={onStatusChange}
            />
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}

function DialogTabs({
  alert,
  detailView,
  onDetailViewChange,
}: {
  alert: Alert;
  detailView: AlertDetailView;
  onDetailViewChange: (view: AlertDetailView) => void;
}) {
  return (
    <div className="border-b px-6 pt-3">
      <div className="flex flex-wrap items-center gap-2">
        <div className="flex flex-wrap gap-2">
          <Badge className={getSeverityBadgeClass(alert.severity)}>
            {severityLabels[alert.severity]}
          </Badge>
          <Badge variant="outline" className={getStatusBadgeClass(alert.status)}>
            {statusLabelForRecord(alert.status)}
          </Badge>
        </div>
      </div>
      <div className="mt-4 flex gap-6">
        <button
          type="button"
          onClick={() => onDetailViewChange("details")}
          className={modalTabClass(detailView === "details")}
        >
          事件內容
        </button>
        <button
          type="button"
          onClick={() => onDetailViewChange("mcp")}
          className={modalTabClass(detailView === "mcp")}
        >
          <Search className="size-4" />
          資安偵探
        </button>
      </div>
    </div>
  );
}

"use client";

import { TechnicalAlertDetails } from "@/components/dashboard/technical-alert-details";
import type { Alert } from "@/lib/types";
import { AlertFactGrid } from "./alert-fact-grid";
import {
  ExpandHint,
  expandablePanelClass,
  expandableSummaryClass,
  RotatingChevron,
} from "./alert-table-model";

interface AlertDetailsPanelProps {
  alert: Alert;
  relatedIp: string;
}

export function AlertDetailsPanel({ alert, relatedIp }: AlertDetailsPanelProps) {
  return (
    <div className="space-y-5">
      <AlertFactGrid alert={alert} relatedIp={relatedIp} showAgentIp />

      <div className="grid gap-5 lg:grid-cols-3">
        <div>
          <h4 className="text-sm font-semibold">摘要</h4>
          <p className="mt-2 text-sm leading-6 text-muted-foreground">{alert.summary}</p>
        </div>
        <div>
          <h4 className="text-sm font-semibold">業務影響</h4>
          <p className="mt-2 text-sm leading-6 text-muted-foreground">{alert.business_impact}</p>
        </div>
        <div>
          <h4 className="text-sm font-semibold">建議處理步驟</h4>
          <p className="mt-2 whitespace-pre-line text-sm leading-6 text-muted-foreground">
            {alert.recommended_action}
          </p>
        </div>
      </div>

      <details key={`technical-details-${alert.id}`} className={expandablePanelClass}>
        <summary className={expandableSummaryClass}>
          <span className="inline-flex items-center gap-2">
            <RotatingChevron />
            IT 技術明細與原始 Log
          </span>
          <ExpandHint />
        </summary>
        <div className="mt-4">
          <TechnicalAlertDetails alert={alert} compact />
        </div>
      </details>
    </div>
  );
}

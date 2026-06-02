"use client";

import { format } from "date-fns";
import { zhTW } from "date-fns/locale";
import { compactIp } from "@/lib/investigation";
import type { Alert } from "@/lib/types";

interface AlertFactGridProps {
  alert: Alert;
  relatedIp: string;
  showAgentIp?: boolean;
}

export function AlertFactGrid({ alert, relatedIp, showAgentIp = false }: AlertFactGridProps) {
  return (
    <div className="rounded-lg border bg-muted/30 p-4">
      <div className="grid gap-4 lg:grid-cols-3">
        <div>
          <div className="text-xs text-muted-foreground">端點</div>
          <div className="mt-1 text-sm font-medium">{alert.agent_name}</div>
          {showAgentIp && (
            <div className="mt-1 break-all text-xs text-muted-foreground">
              {compactIp(alert.agent_ip)}
            </div>
          )}
        </div>
        <div>
          <div className="text-xs text-muted-foreground">
            {relatedIp ? "來源 IP" : "時間"}
          </div>
          <div className="mt-1 text-sm font-medium">
            {relatedIp || format(new Date(alert.timestamp), "yyyy/MM/dd HH:mm:ss", { locale: zhTW })}
          </div>
          {showAgentIp && relatedIp && (
            <div className="mt-1 text-xs text-muted-foreground">
              {format(new Date(alert.timestamp), "yyyy/MM/dd HH:mm:ss", { locale: zhTW })}
            </div>
          )}
        </div>
        <div>
          <div className="text-xs text-muted-foreground">Rule</div>
          <div className="mt-1 text-sm font-medium">
            {alert.rule_id}
            {alert.rule_level != null ? ` / L${alert.rule_level}` : ""}
          </div>
        </div>
      </div>
    </div>
  );
}

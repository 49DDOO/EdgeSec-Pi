"use client";

import { useState, useEffect } from "react";
import { X, Bell, AlertTriangle, ShieldAlert, Info, AlertCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import type { Alert, SeverityLevel } from "@/lib/types";
import { severityLabels } from "@/lib/mock-data";
import { format } from "date-fns";
import { zhTW } from "date-fns/locale";

interface NotificationPanelProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  alerts: Alert[];
  onAlertClick?: (alert: Alert) => void;
}

const getSeverityIcon = (severity: SeverityLevel) => {
  switch (severity) {
    case "critical":
      return <ShieldAlert className="size-4 text-critical" />;
    case "high":
      return <AlertTriangle className="size-4 text-high" />;
    case "medium":
      return <Info className="size-4 text-medium" />;
    case "low":
      return <AlertCircle className="size-4 text-low" />;
  }
};

const getSeverityBadgeClass = (severity: SeverityLevel) => {
  switch (severity) {
    case "critical":
      return "bg-critical text-critical-foreground";
    case "high":
      return "bg-high text-high-foreground";
    case "medium":
      return "bg-medium text-medium-foreground";
    case "low":
      return "bg-low text-low-foreground";
  }
};

export function NotificationPanel({ open, onOpenChange, alerts, onAlertClick }: NotificationPanelProps) {
  const pendingAlerts = alerts.filter((a) => a.status === "pending");
  const recentAlerts = alerts.slice(0, 10);

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent>
        <SheetHeader>
          <SheetTitle className="flex items-center gap-2">
            <Bell className="size-5" />
            通知中心
          </SheetTitle>
          <SheetDescription>
            {pendingAlerts.length > 0 ? (
              <span className="text-destructive">
                {pendingAlerts.length} 則待處理通知
              </span>
            ) : (
              "目前沒有待處理通知"
            )}
          </SheetDescription>
        </SheetHeader>
        
        <ScrollArea className="mt-6 h-[calc(100vh-10rem)]">
          <div className="space-y-4 pr-4">
            {pendingAlerts.length > 0 && (
              <>
                <h4 className="text-sm font-semibold text-muted-foreground">待處理</h4>
                {pendingAlerts.map((alert) => (
                  <div
                    key={alert.id}
                    className="cursor-pointer rounded-lg border border-destructive/20 bg-destructive/5 p-4 transition-colors hover:bg-destructive/10"
                    onClick={() => onAlertClick?.(alert)}
                  >
                    <div className="flex items-start gap-3">
                      {getSeverityIcon(alert.severity)}
                      <div className="flex-1 space-y-1">
                        <div className="flex items-center justify-between">
                          <p className="text-sm font-medium">{alert.rule_description}</p>
                          <Badge className={`${getSeverityBadgeClass(alert.severity)} text-xs`}>
                            {severityLabels[alert.severity]}
                          </Badge>
                        </div>
                        <p className="text-xs text-muted-foreground line-clamp-2">
                          {alert.summary}
                        </p>
                        <p className="text-xs text-muted-foreground">
                          {alert.agent_name} - {format(new Date(alert.timestamp), "MM/dd HH:mm", { locale: zhTW })}
                        </p>
                      </div>
                    </div>
                  </div>
                ))}
                <Separator className="my-4" />
              </>
            )}
            
            <h4 className="text-sm font-semibold text-muted-foreground">最近告警</h4>
            {recentAlerts.map((alert) => (
              <div
                key={alert.id}
                className="cursor-pointer rounded-lg border p-4 transition-colors hover:bg-muted/50"
                onClick={() => onAlertClick?.(alert)}
              >
                <div className="flex items-start gap-3">
                  {getSeverityIcon(alert.severity)}
                  <div className="flex-1 space-y-1">
                    <div className="flex items-center justify-between">
                      <p className="text-sm font-medium">{alert.rule_description}</p>
                      <Badge variant="outline" className="text-xs">
                        {severityLabels[alert.severity]}
                      </Badge>
                    </div>
                    <p className="text-xs text-muted-foreground line-clamp-1">
                      {alert.summary}
                    </p>
                    <p className="text-xs text-muted-foreground">
                      {format(new Date(alert.timestamp), "MM/dd HH:mm", { locale: zhTW })}
                    </p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </ScrollArea>
      </SheetContent>
    </Sheet>
  );
}

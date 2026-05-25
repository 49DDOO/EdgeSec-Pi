"use client";

import { AlertTriangle, ShieldAlert, ShieldCheck, Info, TrendingUp, Clock } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import type { RiskSummary } from "@/lib/types";
import { severityLabels } from "@/lib/labels";

interface RiskOverviewProps {
  data: RiskSummary;
}

export function RiskOverview({ data }: RiskOverviewProps) {
  const getRiskIcon = () => {
    switch (data.level) {
      case "critical":
        return <ShieldAlert className="size-8 text-critical" />;
      case "high":
        return <AlertTriangle className="size-8 text-high" />;
      case "medium":
        return <Info className="size-8 text-medium" />;
      default:
        return <ShieldCheck className="size-8 text-success" />;
    }
  };

  const getRiskBadgeVariant = () => {
    switch (data.level) {
      case "critical":
        return "destructive";
      case "high":
        return "default";
      case "medium":
        return "secondary";
      default:
        return "outline";
    }
  };

  const getRiskColorClass = () => {
    switch (data.level) {
      case "critical":
        return "text-critical";
      case "high":
        return "text-high";
      case "medium":
        return "text-medium";
      default:
        return "text-success";
    }
  };

  return (
    <Card className="relative overflow-hidden">
      <CardHeader className="pb-2">
        <CardDescription className="flex items-center gap-2">
          <Clock className="size-4" />
          今日風險摘要
        </CardDescription>
        <CardTitle className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            {getRiskIcon()}
            <div>
              <span className={`text-3xl font-bold ${getRiskColorClass()}`}>
                {severityLabels[data.level]}
              </span>
              <Badge variant={getRiskBadgeVariant()} className="ml-2">
                風險分數: {data.score}
              </Badge>
            </div>
          </div>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="mt-4 grid grid-cols-2 gap-4 sm:grid-cols-4">
          <div className="flex flex-col items-center rounded-lg bg-critical/10 p-3">
            <span className="text-2xl font-bold text-critical">{data.critical_count}</span>
            <span className="text-xs text-muted-foreground">危急</span>
          </div>
          <div className="flex flex-col items-center rounded-lg bg-high/10 p-3">
            <span className="text-2xl font-bold text-high">{data.high_count}</span>
            <span className="text-xs text-muted-foreground">高風險</span>
          </div>
          <div className="flex flex-col items-center rounded-lg bg-medium/10 p-3">
            <span className="text-2xl font-bold text-medium">{data.medium_count}</span>
            <span className="text-xs text-muted-foreground">中風險</span>
          </div>
          <div className="flex flex-col items-center rounded-lg bg-low/10 p-3">
            <span className="text-2xl font-bold text-low">{data.low_count}</span>
            <span className="text-xs text-muted-foreground">低風險</span>
          </div>
        </div>

        <div className="mt-4 flex items-center justify-between border-t pt-4">
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <TrendingUp className="size-4" />
            今日告警總數
          </div>
          <span className="text-lg font-semibold">{data.total_alerts_today}</span>
        </div>
      </CardContent>
    </Card>
  );
}

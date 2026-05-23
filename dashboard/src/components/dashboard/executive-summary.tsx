"use client";

import { ShieldCheck, ShieldAlert, AlertTriangle, Minus, Clock } from "lucide-react";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import type { RiskSummary, Alert } from "@/lib/types";

interface ExecutiveSummaryProps {
  data: RiskSummary;
  alerts: Alert[];
  endpointCount: number;
}

export function ExecutiveSummary({ data, alerts, endpointCount }: ExecutiveSummaryProps) {
  const pendingAlerts = alerts.filter((a) => a.status === "pending");
  const criticalPending = pendingAlerts.filter((a) => a.severity === "critical");
  
  // 根據風險等級決定整體狀態
  const getOverallStatus = () => {
    if (data.critical_count > 0) {
      return {
        emoji: "shield-alert",
        title: "需要立即關注",
        subtitle: "公司資安有緊急狀況需要處理",
        color: "text-critical",
        bgColor: "bg-critical/10",
        borderColor: "border-critical/30",
      };
    }
    if (data.high_count > 0) {
      return {
        emoji: "alert-triangle",
        title: "請留意",
        subtitle: "有重要事項需要確認",
        color: "text-high",
        bgColor: "bg-high/10",
        borderColor: "border-high/30",
      };
    }
    if (data.medium_count > 0) {
      return {
        emoji: "minus",
        title: "尚可",
        subtitle: "有一些小問題，但不急迫",
        color: "text-medium",
        bgColor: "bg-medium/10",
        borderColor: "border-medium/30",
      };
    }
    return {
      emoji: "shield-check",
      title: "一切正常",
      subtitle: "公司資安狀況良好",
      color: "text-success",
      bgColor: "bg-success/10",
      borderColor: "border-success/30",
    };
  };

  const status = getOverallStatus();

  const getStatusIcon = () => {
    switch (status.emoji) {
      case "shield-alert":
        return <ShieldAlert className="size-16" />;
      case "alert-triangle":
        return <AlertTriangle className="size-16" />;
      case "minus":
        return <Minus className="size-16" />;
      default:
        return <ShieldCheck className="size-16" />;
    }
  };

  // 一句話摘要
  const getOneLinerSummary = () => {
    if (criticalPending.length > 0) {
      return `有 ${criticalPending.length} 件緊急資安事件，可能影響公司營運`;
    }
    if (pendingAlerts.length > 0) {
      return `有 ${pendingAlerts.length} 件待處理事項，建議請 IT 確認`;
    }
    return "目前沒有需要您關注的資安問題";
  };

  return (
    <Card className={`relative overflow-hidden border-2 ${status.borderColor}`}>
      <CardHeader className="pb-2">
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <Clock className="size-4" />
          今日資安狀況
        </div>
      </CardHeader>
      <CardContent>
        <div className="flex flex-col items-center gap-4 py-4 text-center md:flex-row md:text-left">
          {/* 大圖示 */}
          <div className={`flex size-24 items-center justify-center rounded-full ${status.bgColor} ${status.color}`}>
            {getStatusIcon()}
          </div>
          
          {/* 主要訊息 */}
          <div className="flex-1">
            <h2 className={`text-3xl font-bold ${status.color}`}>
              {status.title}
            </h2>
            <p className="mt-1 text-lg text-muted-foreground">
              {status.subtitle}
            </p>
            <p className="mt-3 text-base">
              {getOneLinerSummary()}
            </p>
          </div>
        </div>

        {/* 簡化統計 - 只顯示老闆需要知道的 */}
        <div className="mt-4 grid grid-cols-3 gap-4 border-t pt-4">
          <div className="text-center">
            <div className="text-sm text-muted-foreground">需要處理</div>
            <div className={`text-2xl font-bold ${pendingAlerts.length > 0 ? "text-destructive" : "text-success"}`}>
              {pendingAlerts.length} 件
            </div>
          </div>
          <div className="text-center">
            <div className="text-sm text-muted-foreground">監控設備</div>
            <div className="text-2xl font-bold">{endpointCount} 台</div>
          </div>
          <div className="text-center">
            <div className="text-sm text-muted-foreground">今日事件</div>
            <div className="text-2xl font-bold">{data.total_alerts_today} 件</div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

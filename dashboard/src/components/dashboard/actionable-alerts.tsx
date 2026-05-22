"use client";

import { format } from "date-fns";
import { zhTW } from "date-fns/locale";
import {
  AlertTriangle,
  ShieldAlert,
  CheckCircle2,
  XCircle,
  ArrowRight,
  Building2,
  Wrench,
} from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import type { Alert, AlertStatus } from "@/lib/types";
import { toast } from "sonner";

interface ActionableAlertsProps {
  alerts: Alert[];
  onStatusChange?: (alertId: string, newStatus: AlertStatus) => void;
}

// 將技術術語轉換成白話文
const getPlainLanguageTitle = (alert: Alert) => {
  const map: Record<string, string> = {
    "SSH 暴力破解嘗試": "有人嘗試入侵公司電腦",
    "可疑檔案變更偵測": "重要檔案被修改了",
    "異常網路流量": "網路有異常傳輸",
    "防火牆規則變更": "防火牆設定被改動",
    "軟體漏洞偵測": "軟體有安全漏洞",
    "使用者權限提升": "員工權限被提升",
  };
  return map[alert.rule_description] || alert.rule_description;
};

// 業務影響的白話版
const getPlainBusinessImpact = (alert: Alert) => {
  const impactMap: Record<string, string> = {
    critical: "可能嚴重影響公司營運或資料安全",
    high: "可能影響部分業務或系統",
    medium: "需要留意但不緊急",
    low: "輕微問題，可安排時間處理",
  };
  return impactMap[alert.severity];
};

export function ActionableAlerts({ alerts, onStatusChange }: ActionableAlertsProps) {
  const pendingAlerts = alerts.filter((a) => a.status === "pending");
  
  const handleAction = (alertId: string, action: "it" | "ok" | "false") => {
    const statusMap: Record<string, AlertStatus> = {
      it: "acknowledged",
      ok: "resolved",
      false: "false_positive",
    };
    const labelMap: Record<string, string> = {
      it: "已轉交 IT 處理",
      ok: "已標記為正常",
      false: "已標記為誤報",
    };
    onStatusChange?.(alertId, statusMap[action]);
    toast.success(labelMap[action]);
  };

  if (pendingAlerts.length === 0) {
    return (
      <Card>
        <CardContent className="flex flex-col items-center justify-center py-12 text-center">
          <CheckCircle2 className="mb-4 size-16 text-success" />
          <h3 className="text-xl font-semibold">沒有待處理事項</h3>
          <p className="mt-2 text-muted-foreground">
            目前沒有需要您決定的資安事件
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <AlertTriangle className="size-5 text-high" />
          需要您決定的事項
        </CardTitle>
        <CardDescription>
          以下事項需要您確認後續處理方式
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {pendingAlerts.map((alert, index) => (
          <div key={alert.id}>
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
                <Badge
                  variant={alert.severity === "critical" ? "destructive" : "secondary"}
                >
                  {alert.severity === "critical" ? "緊急" : "重要"}
                </Badge>
              </div>

              {/* 一句話說明影響 */}
              <div className="rounded-lg bg-muted/50 p-3">
                <p className="text-sm">
                  <span className="font-medium">影響：</span>
                  {getPlainBusinessImpact(alert)}
                </p>
                <p className="mt-1 text-sm text-muted-foreground">
                  發生於 {alert.agent_name}（{alert.purpose || "公司設備"}）
                </p>
              </div>

              {/* 簡化的動作按鈕 */}
              <div className="flex flex-wrap gap-2">
                <Button
                  size="sm"
                  onClick={() => handleAction(alert.id, "it")}
                  className="gap-1"
                >
                  <Wrench data-icon="inline-start" />
                  交給 IT 處理
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => handleAction(alert.id, "ok")}
                  className="gap-1"
                >
                  <CheckCircle2 data-icon="inline-start" />
                  這是正常操作
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => handleAction(alert.id, "false")}
                  className="gap-1 text-muted-foreground"
                >
                  <XCircle data-icon="inline-start" />
                  誤報
                </Button>
              </div>
            </div>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}

"use client";

import {
  Activity,
  Database,
  Bell,
  Brain,
  Link2,
} from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { Separator } from "@/components/ui/separator";
import type { SystemHealth, NotificationConfig } from "@/lib/types";
import { formatDistanceToNow } from "date-fns";
import { zhTW } from "date-fns/locale";

interface SystemStatusProps {
  health: SystemHealth;
  notifications: NotificationConfig;
  onNotificationChange?: (key: keyof NotificationConfig, value: boolean) => void;
}

const getHealthStatusBadge = (status: "healthy" | "degraded" | "down") => {
  switch (status) {
    case "healthy":
      return (
        <Badge variant="outline" className="bg-success/10 text-success border-success/20">
          正常
        </Badge>
      );
    case "degraded":
      return (
        <Badge variant="outline" className="bg-high/10 text-high border-high/20">
          降級
        </Badge>
      );
    case "down":
      return (
        <Badge variant="outline" className="bg-destructive/10 text-destructive border-destructive/20">
          停止
        </Badge>
      );
  }
};

const getConnectionStatusBadge = (status: "connected" | "disconnected") => {
  if (status === "connected") {
    return (
      <Badge variant="outline" className="bg-success/10 text-success border-success/20">
        已連線
      </Badge>
    );
  }
  return (
    <Badge variant="outline" className="bg-destructive/10 text-destructive border-destructive/20">
      已斷線
    </Badge>
  );
};

export function SystemStatus({ health, notifications, onNotificationChange }: SystemStatusProps) {
  return (
    <div className="grid gap-4 md:grid-cols-2">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Activity className="size-5" />
            系統健康狀態
          </CardTitle>
          <CardDescription>各服務運行狀況</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Bell className="size-5 text-muted-foreground" />
              <span>通知服務</span>
            </div>
            {getHealthStatusBadge(health.notification_service)}
          </div>

          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Brain className="size-5 text-muted-foreground" />
              <span>LLM 分析服務</span>
            </div>
            {getHealthStatusBadge(health.llm_service)}
          </div>

          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Link2 className="size-5 text-muted-foreground" />
              <span>Wazuh 連線</span>
            </div>
            {getConnectionStatusBadge(health.wazuh_connection)}
          </div>

          <Separator />

          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Activity className="size-5 text-muted-foreground" />
              <span>分析佇列</span>
            </div>
            <Badge variant="secondary">{health.analysis_queue} 項待處理</Badge>
          </div>

          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Database className="size-5 text-muted-foreground" />
              <span>CVE 資料庫</span>
            </div>
            <span className="text-sm text-muted-foreground">
              {formatDistanceToNow(new Date(health.cve_database_updated), {
                addSuffix: true,
                locale: zhTW,
              })}
              更新
            </span>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Bell className="size-5" />
            通知設定
          </CardTitle>
          <CardDescription>告警通知管道設定</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="flex size-8 items-center justify-center rounded-md bg-[#00C300]/10">
                <span className="text-sm font-bold text-[#00C300]">L</span>
              </div>
              <span>LINE Notify</span>
            </div>
            <Switch
              checked={notifications.line}
              onCheckedChange={(checked) => onNotificationChange?.("line", checked)}
            />
          </div>

          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="flex size-8 items-center justify-center rounded-md bg-[#4A154B]/10">
                <span className="text-sm font-bold text-[#4A154B]">S</span>
              </div>
              <span>Slack</span>
            </div>
            <Switch
              checked={notifications.slack}
              onCheckedChange={(checked) => onNotificationChange?.("slack", checked)}
            />
          </div>

          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="flex size-8 items-center justify-center rounded-md bg-[#0088cc]/10">
                <span className="text-sm font-bold text-[#0088cc]">T</span>
              </div>
              <span>Telegram</span>
            </div>
            <Switch
              checked={notifications.telegram}
              onCheckedChange={(checked) => onNotificationChange?.("telegram", checked)}
            />
          </div>

          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="flex size-8 items-center justify-center rounded-md bg-primary/10">
                <span className="text-sm font-bold text-primary">@</span>
              </div>
              <span>Email</span>
            </div>
            <Switch
              checked={notifications.email}
              onCheckedChange={(checked) => onNotificationChange?.("email", checked)}
            />
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

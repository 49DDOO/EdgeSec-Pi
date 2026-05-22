"use client";

import { useState } from "react";
import { Header } from "@/components/dashboard/header";
import { ExecutiveSummary } from "@/components/dashboard/executive-summary";
import { ActionableAlerts } from "@/components/dashboard/actionable-alerts";
import { DeviceStatus } from "@/components/dashboard/device-status";
import { AlertTrendChart } from "@/components/dashboard/alert-trend-chart";
import { AlertsTable } from "@/components/dashboard/alerts-table";
import { EndpointsMonitor } from "@/components/dashboard/endpoints-monitor";
import { SystemStatus } from "@/components/dashboard/system-status";
import { NotificationPanel } from "@/components/dashboard/notification-panel";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  mockAlerts,
  mockEndpoints,
  mockRiskSummary,
  mockSystemHealth,
  mockNotificationConfig,
  mockAlertTrends,
} from "@/lib/mock-data";
import type { Alert, AlertStatus, NotificationConfig } from "@/lib/types";
import { LayoutDashboard, AlertCircle, Server, Settings, Wrench } from "lucide-react";

export default function DashboardPage() {
  const [alerts, setAlerts] = useState<Alert[]>(mockAlerts);
  const [notifications, setNotifications] = useState<NotificationConfig>(mockNotificationConfig);
  const [notificationPanelOpen, setNotificationPanelOpen] = useState(false);

  const pendingCount = alerts.filter((a) => a.status === "pending").length;

  const handleStatusChange = (alertId: string, newStatus: AlertStatus) => {
    setAlerts((prev) =>
      prev.map((alert) =>
        alert.id === alertId ? { ...alert, status: newStatus } : alert
      )
    );
  };

  const handleNotificationChange = (key: keyof NotificationConfig, value: boolean) => {
    setNotifications((prev) => ({ ...prev, [key]: value }));
  };

  return (
    <div className="min-h-screen bg-background">
      <Header
        pendingCount={pendingCount}
        onNotificationClick={() => setNotificationPanelOpen(true)}
      />

      <main className="container mx-auto px-4 py-6 md:px-6">
        <Tabs defaultValue="boss" className="space-y-6">
          <TabsList className="grid w-full grid-cols-5 lg:w-auto lg:inline-flex">
            <TabsTrigger value="boss" className="gap-2">
              <LayoutDashboard className="size-4" />
              <span className="hidden sm:inline">總覽</span>
            </TabsTrigger>
            <TabsTrigger value="alerts" className="gap-2">
              <AlertCircle className="size-4" />
              <span className="hidden sm:inline">告警</span>
              {pendingCount > 0 && (
                <span className="ml-1 flex size-5 items-center justify-center rounded-full bg-destructive text-xs text-destructive-foreground">
                  {pendingCount}
                </span>
              )}
            </TabsTrigger>
            <TabsTrigger value="endpoints" className="gap-2">
              <Server className="size-4" />
              <span className="hidden sm:inline">設備</span>
            </TabsTrigger>
            <TabsTrigger value="it" className="gap-2">
              <Wrench className="size-4" />
              <span className="hidden sm:inline">IT 詳細</span>
            </TabsTrigger>
            <TabsTrigger value="system" className="gap-2">
              <Settings className="size-4" />
              <span className="hidden sm:inline">系統</span>
            </TabsTrigger>
          </TabsList>

          {/* 老闆視角 - 簡單明瞭 */}
          <TabsContent value="boss" className="space-y-6">
            <ExecutiveSummary data={mockRiskSummary} alerts={alerts} />
            <div className="grid gap-6 lg:grid-cols-2">
              <ActionableAlerts
                alerts={alerts}
                onStatusChange={handleStatusChange}
              />
              <DeviceStatus endpoints={mockEndpoints} />
            </div>
          </TabsContent>

          {/* 告警頁面 - 簡化版 */}
          <TabsContent value="alerts">
            <ActionableAlerts
              alerts={alerts}
              onStatusChange={handleStatusChange}
            />
          </TabsContent>

          {/* 設備狀態 */}
          <TabsContent value="endpoints">
            <DeviceStatus endpoints={mockEndpoints} />
          </TabsContent>

          {/* IT 詳細視角 - 保留技術細節 */}
          <TabsContent value="it" className="space-y-6">
            <div className="grid gap-6 lg:grid-cols-2">
              <AlertTrendChart data={mockAlertTrends} />
              <EndpointsMonitor endpoints={mockEndpoints} />
            </div>
            <AlertsTable alerts={alerts} onStatusChange={handleStatusChange} />
          </TabsContent>

          {/* 系統設定 */}
          <TabsContent value="system">
            <SystemStatus
              health={mockSystemHealth}
              notifications={notifications}
              onNotificationChange={handleNotificationChange}
            />
          </TabsContent>
        </Tabs>
      </main>

      <NotificationPanel
        open={notificationPanelOpen}
        onOpenChange={setNotificationPanelOpen}
        alerts={alerts}
      />
    </div>
  );
}

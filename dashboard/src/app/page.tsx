"use client";

import { useState } from "react";
import { Header } from "@/components/dashboard/header";
import { RiskOverview } from "@/components/dashboard/risk-overview";
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
import { LayoutDashboard, AlertCircle, Server, Settings } from "lucide-react";

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
        <Tabs defaultValue="overview" className="space-y-6">
          <TabsList className="grid w-full grid-cols-4 lg:w-auto lg:inline-flex">
            <TabsTrigger value="overview" className="gap-2">
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
              <span className="hidden sm:inline">端點</span>
            </TabsTrigger>
            <TabsTrigger value="system" className="gap-2">
              <Settings className="size-4" />
              <span className="hidden sm:inline">系統</span>
            </TabsTrigger>
          </TabsList>

          <TabsContent value="overview" className="space-y-6">
            <div className="grid gap-6 lg:grid-cols-2">
              <RiskOverview data={mockRiskSummary} />
              <AlertTrendChart data={mockAlertTrends} />
            </div>
            <div className="grid gap-6 lg:grid-cols-2">
              <AlertsTable
                alerts={alerts.filter((a) => a.status === "pending").slice(0, 3)}
                onStatusChange={handleStatusChange}
              />
              <EndpointsMonitor endpoints={mockEndpoints.slice(0, 4)} />
            </div>
          </TabsContent>

          <TabsContent value="alerts">
            <AlertsTable alerts={alerts} onStatusChange={handleStatusChange} />
          </TabsContent>

          <TabsContent value="endpoints">
            <EndpointsMonitor endpoints={mockEndpoints} />
          </TabsContent>

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

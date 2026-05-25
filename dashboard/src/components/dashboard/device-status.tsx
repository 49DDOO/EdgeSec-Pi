"use client";

import { Monitor, CheckCircle2, AlertCircle, XCircle } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import type { Endpoint } from "@/lib/types";

interface DeviceStatusProps {
  endpoints: Endpoint[];
}

export function DeviceStatus({ endpoints }: DeviceStatusProps) {
  const onlineCount = endpoints.filter((e) => e.status === "online").length;
  const warningCount = endpoints.filter((e) => e.status === "warning").length;
  const offlineCount = endpoints.filter((e) => e.status === "offline").length;

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "online":
        return <CheckCircle2 className="size-4 text-success" />;
      case "warning":
        return <AlertCircle className="size-4 text-medium" />;
      default:
        return <XCircle className="size-4 text-destructive" />;
    }
  };

  const getStatusText = (status: string) => {
    switch (status) {
      case "online":
        return "正常運作";
      case "warning":
        return "需要注意";
      default:
        return "離線";
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Monitor className="size-5" />
          公司設備狀態
        </CardTitle>
        <CardDescription>
          目前監控中的設備運作狀況
        </CardDescription>
      </CardHeader>
      <CardContent>
        {/* 總覽 */}
        <div className="mb-4 flex gap-4 rounded-lg bg-muted/50 p-3">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="size-4 text-success" />
            <span className="text-sm">{onlineCount} 台正常</span>
          </div>
          {warningCount > 0 && (
            <div className="flex items-center gap-2">
              <AlertCircle className="size-4 text-medium" />
              <span className="text-sm">{warningCount} 台需注意</span>
            </div>
          )}
          {offlineCount > 0 && (
            <div className="flex items-center gap-2">
              <XCircle className="size-4 text-destructive" />
              <span className="text-sm">{offlineCount} 台離線</span>
            </div>
          )}
        </div>

        {/* 設備列表 - 簡化版 */}
        <div className="divide-y divide-border">
          {endpoints.map((endpoint) => (
            <div
              key={endpoint.id}
              className="flex items-center justify-between py-3"
            >
              <div className="flex items-center gap-3">
                {getStatusIcon(endpoint.status)}
                <div>
                  <div className="font-medium">{endpoint.purpose || endpoint.name}</div>
                  <div className="text-sm text-muted-foreground">
                    {endpoint.name}
                  </div>
                </div>
              </div>
              <span className={`text-sm ${
                endpoint.status === "online" ? "text-success" :
                endpoint.status === "warning" ? "text-medium" : "text-destructive"
              }`}>
                {getStatusText(endpoint.status)}
              </span>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

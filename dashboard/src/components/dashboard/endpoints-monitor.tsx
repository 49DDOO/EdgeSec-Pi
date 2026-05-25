"use client";

import { Server, Wifi, WifiOff, AlertTriangle, CheckCircle2 } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import type { Endpoint, EndpointStatus } from "@/lib/types";
import { formatDistanceToNow } from "date-fns";
import { zhTW } from "date-fns/locale";

interface EndpointsMonitorProps {
  endpoints: Endpoint[];
}

const getStatusIcon = (status: EndpointStatus) => {
  switch (status) {
    case "online":
      return <Wifi className="size-4 text-success" />;
    case "offline":
      return <WifiOff className="size-4 text-destructive" />;
    case "warning":
      return <AlertTriangle className="size-4 text-high" />;
  }
};

const getStatusBadge = (status: EndpointStatus) => {
  switch (status) {
    case "online":
      return (
        <Badge variant="outline" className="bg-success/10 text-success border-success/20">
          線上
        </Badge>
      );
    case "offline":
      return (
        <Badge variant="outline" className="bg-destructive/10 text-destructive border-destructive/20">
          離線
        </Badge>
      );
    case "warning":
      return (
        <Badge variant="outline" className="bg-high/10 text-high border-high/20">
          警告
        </Badge>
      );
  }
};

const getScaScoreColor = (score: number | null | undefined) => {
  if (score == null) return "text-muted-foreground";
  if (score >= 80) return "text-success";
  if (score >= 60) return "text-high";
  if (score >= 40) return "text-medium";
  return "text-destructive";
};

const getScaScoreBg = (score: number | null | undefined) => {
  if (score == null) return "bg-muted";
  if (score >= 80) return "bg-success";
  if (score >= 60) return "bg-high";
  if (score >= 40) return "bg-medium";
  return "bg-destructive";
};

export function EndpointsMonitor({ endpoints }: EndpointsMonitorProps) {
  const onlineCount = endpoints.filter((e) => e.status === "online").length;
  const warningCount = endpoints.filter((e) => e.status === "warning").length;
  const offlineCount = endpoints.filter((e) => e.status === "offline").length;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Server className="size-5" />
          端點監控
        </CardTitle>
        <CardDescription className="flex items-center gap-4">
          <span className="flex items-center gap-1">
            <CheckCircle2 className="size-4 text-success" />
            {onlineCount} 線上
          </span>
          <span className="flex items-center gap-1">
            <AlertTriangle className="size-4 text-high" />
            {warningCount} 警告
          </span>
          <span className="flex items-center gap-1">
            <WifiOff className="size-4 text-destructive" />
            {offlineCount} 離線
          </span>
        </CardDescription>
      </CardHeader>
      <CardContent>
        <ScrollArea className="h-[400px] pr-4">
          <div className="space-y-3">
            {endpoints.map((endpoint) => (
              <div
                key={endpoint.id}
                className="flex items-center gap-4 rounded-lg border p-4 transition-colors hover:bg-muted/50"
              >
                {/*
                  SCA 是安全設定分數，和 Agent 在線狀態不同。不要用連線
                  狀態去假裝安全分數，否則會把 Wazuh 60 分顯示成 100 分。
                */}
                <Tooltip>
                  <TooltipTrigger render={<Avatar className="size-10" />}>
                    <AvatarFallback className="bg-muted text-muted-foreground">
                      {getStatusIcon(endpoint.status)}
                    </AvatarFallback>
                  </TooltipTrigger>
                  <TooltipContent>
                    <p>{endpoint.status === "online" ? "連線正常" : endpoint.status === "warning" ? "需要注意" : "已離線"}</p>
                  </TooltipContent>
                </Tooltip>

                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <h4 className="font-medium truncate">{endpoint.name}</h4>
                    {getStatusBadge(endpoint.status)}
                  </div>
                  <div className="mt-1 flex flex-wrap items-center gap-x-4 gap-y-1 text-sm text-muted-foreground">
                    <span>
                      {endpoint.ip || "IP 未回報"}
                      {endpoint.ip_is_loopback ? "（Agent 尚未回報內網位址）" : ""}
                    </span>
                    <span className="hidden sm:inline">{endpoint.os}</span>
                    <span className="hidden md:inline">{endpoint.purpose}</span>
                  </div>
                  <div className="mt-1 text-xs text-muted-foreground">
                    最後同步:{" "}
                    {formatDistanceToNow(new Date(endpoint.last_sync), {
                      addSuffix: true,
                      locale: zhTW,
                    })}
                  </div>
                </div>

                <div className="flex flex-col items-end gap-1">
                  <Tooltip>
                    <TooltipTrigger render={<div className="flex items-center gap-2" />}>
                      <span className={`text-lg font-bold ${getScaScoreColor(endpoint.sca_score)}`}>
                        {endpoint.sca_score ?? "-"}
                      </span>
                      <div className="h-2 w-16 overflow-hidden rounded-full bg-muted">
                        <div
                          className={`h-full ${getScaScoreBg(endpoint.sca_score)}`}
                          style={{ width: `${endpoint.sca_score ?? 0}%` }}
                        />
                      </div>
                    </TooltipTrigger>
                    <TooltipContent>
                      <p>
                        {endpoint.sca_score == null
                          ? "安全設定分數尚未取得"
                          : `安全設定分數: ${endpoint.sca_score}/100`}
                      </p>
                      {endpoint.sca?.policy ? <p>{endpoint.sca.policy}</p> : null}
                    </TooltipContent>
                  </Tooltip>
                  <span className="text-xs text-muted-foreground">安全設定 / v{endpoint.version}</span>
                </div>
              </div>
            ))}
          </div>
        </ScrollArea>
      </CardContent>
    </Card>
  );
}

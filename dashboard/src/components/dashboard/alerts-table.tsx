"use client";

import { useState } from "react";
import { format } from "date-fns";
import { zhTW } from "date-fns/locale";
import {
  AlertCircle,
  AlertTriangle,
  Info,
  ShieldAlert,
  CheckCircle2,
  XCircle,
  ChevronDown,
  ChevronUp,
  Server,
  Search,
  Filter,
} from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import type { Alert, SeverityLevel, AlertStatus } from "@/lib/types";
import { severityLabels, statusLabels } from "@/lib/mock-data";
import { toast } from "sonner";

interface AlertsTableProps {
  alerts: Alert[];
  onStatusChange?: (alertId: string, newStatus: AlertStatus) => void;
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
      return "bg-critical text-critical-foreground hover:bg-critical/80";
    case "high":
      return "bg-high text-high-foreground hover:bg-high/80";
    case "medium":
      return "bg-medium text-medium-foreground hover:bg-medium/80";
    case "low":
      return "bg-low text-low-foreground hover:bg-low/80";
  }
};

const getStatusBadgeClass = (status: AlertStatus) => {
  switch (status) {
    case "pending":
      return "bg-destructive/10 text-destructive border-destructive/20";
    case "acknowledged":
      return "bg-primary/10 text-primary border-primary/20";
    case "resolved":
      return "bg-success/10 text-success border-success/20";
    case "false_positive":
      return "bg-muted text-muted-foreground border-muted";
  }
};

export function AlertsTable({ alerts, onStatusChange }: AlertsTableProps) {
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [filterSeverity, setFilterSeverity] = useState<SeverityLevel | "all">("all");
  const [filterStatus, setFilterStatus] = useState<AlertStatus | "all">("all");

  const filteredAlerts = alerts.filter((alert) => {
    if (filterSeverity !== "all" && alert.severity !== filterSeverity) return false;
    if (filterStatus !== "all" && alert.status !== filterStatus) return false;
    return true;
  });

  const handleStatusChange = (alertId: string, newStatus: AlertStatus) => {
    onStatusChange?.(alertId, newStatus);
    toast.success(`告警狀態已更新為「${statusLabels[newStatus]}」`);
  };

  return (
    <>
      <Card>
        <CardHeader>
          <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <CardTitle>待處理告警</CardTitle>
              <CardDescription>
                共 {filteredAlerts.length} 筆告警
                {filteredAlerts.filter((a) => a.status === "pending").length > 0 && (
                  <span className="ml-1 text-destructive">
                    ({filteredAlerts.filter((a) => a.status === "pending").length} 筆待處理)
                  </span>
                )}
              </CardDescription>
            </div>
            <div className="flex gap-2">
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="outline" size="sm">
                    <Filter data-icon="inline-start" />
                    嚴重程度
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent>
                  <DropdownMenuGroup>
                    <DropdownMenuItem onClick={() => setFilterSeverity("all")}>
                      全部
                    </DropdownMenuItem>
                    <DropdownMenuItem onClick={() => setFilterSeverity("critical")}>
                      危急
                    </DropdownMenuItem>
                    <DropdownMenuItem onClick={() => setFilterSeverity("high")}>
                      高
                    </DropdownMenuItem>
                    <DropdownMenuItem onClick={() => setFilterSeverity("medium")}>
                      中
                    </DropdownMenuItem>
                    <DropdownMenuItem onClick={() => setFilterSeverity("low")}>
                      低
                    </DropdownMenuItem>
                  </DropdownMenuGroup>
                </DropdownMenuContent>
              </DropdownMenu>
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="outline" size="sm">
                    <Filter data-icon="inline-start" />
                    狀態
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent>
                  <DropdownMenuGroup>
                    <DropdownMenuItem onClick={() => setFilterStatus("all")}>
                      全部
                    </DropdownMenuItem>
                    <DropdownMenuItem onClick={() => setFilterStatus("pending")}>
                      待處理
                    </DropdownMenuItem>
                    <DropdownMenuItem onClick={() => setFilterStatus("acknowledged")}>
                      已確認
                    </DropdownMenuItem>
                    <DropdownMenuItem onClick={() => setFilterStatus("resolved")}>
                      已解決
                    </DropdownMenuItem>
                    <DropdownMenuItem onClick={() => setFilterStatus("false_positive")}>
                      誤報
                    </DropdownMenuItem>
                  </DropdownMenuGroup>
                </DropdownMenuContent>
              </DropdownMenu>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <ScrollArea className="h-[400px]">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-[100px]">嚴重程度</TableHead>
                  <TableHead>描述</TableHead>
                  <TableHead className="hidden md:table-cell">端點</TableHead>
                  <TableHead className="hidden lg:table-cell">時間</TableHead>
                  <TableHead>狀態</TableHead>
                  <TableHead className="w-[50px]"></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredAlerts.map((alert) => (
                  <>
                    <TableRow
                      key={alert.id}
                      className="cursor-pointer hover:bg-muted/50"
                      onClick={() => setSelectedAlert(alert)}
                    >
                      <TableCell>
                        <Badge className={getSeverityBadgeClass(alert.severity)}>
                          {getSeverityIcon(alert.severity)}
                          <span className="ml-1">{severityLabels[alert.severity]}</span>
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <div className="font-medium">{alert.rule_description}</div>
                        <div className="text-sm text-muted-foreground line-clamp-1">
                          {alert.summary}
                        </div>
                      </TableCell>
                      <TableCell className="hidden md:table-cell">
                        <div className="flex items-center gap-2">
                          <Server className="size-4 text-muted-foreground" />
                          <span>{alert.agent_name}</span>
                        </div>
                      </TableCell>
                      <TableCell className="hidden lg:table-cell text-muted-foreground">
                        {format(new Date(alert.timestamp), "MM/dd HH:mm", { locale: zhTW })}
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className={getStatusBadgeClass(alert.status)}>
                          {statusLabels[alert.status]}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="size-8"
                          onClick={(e) => {
                            e.stopPropagation();
                            setExpandedId(expandedId === alert.id ? null : alert.id);
                          }}
                        >
                          {expandedId === alert.id ? (
                            <ChevronUp className="size-4" />
                          ) : (
                            <ChevronDown className="size-4" />
                          )}
                        </Button>
                      </TableCell>
                    </TableRow>
                    {expandedId === alert.id && (
                      <TableRow key={`${alert.id}-expanded`}>
                        <TableCell colSpan={6} className="bg-muted/30 p-4">
                          <div className="grid gap-4 md:grid-cols-2">
                            <div>
                              <h4 className="mb-2 font-semibold">業務影響</h4>
                              <p className="text-sm text-muted-foreground">
                                {alert.business_impact}
                              </p>
                            </div>
                            <div>
                              <h4 className="mb-2 font-semibold">建議處理步驟</h4>
                              <p className="whitespace-pre-line text-sm text-muted-foreground">
                                {alert.recommended_action}
                              </p>
                            </div>
                          </div>
                          <div className="mt-4 flex flex-wrap gap-2">
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => handleStatusChange(alert.id, "acknowledged")}
                            >
                              <CheckCircle2 data-icon="inline-start" />
                              正常操作
                            </Button>
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => handleStatusChange(alert.id, "resolved")}
                            >
                              <CheckCircle2 data-icon="inline-start" />
                              已處理
                            </Button>
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => handleStatusChange(alert.id, "false_positive")}
                            >
                              <XCircle data-icon="inline-start" />
                              誤報
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    )}
                  </>
                ))}
              </TableBody>
            </Table>
          </ScrollArea>
        </CardContent>
      </Card>

      <Dialog open={!!selectedAlert} onOpenChange={() => setSelectedAlert(null)}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              {selectedAlert && getSeverityIcon(selectedAlert.severity)}
              {selectedAlert?.rule_description}
            </DialogTitle>
            <DialogDescription>
              規則 ID: {selectedAlert?.rule_id}
            </DialogDescription>
          </DialogHeader>
          {selectedAlert && (
            <div className="space-y-4">
              <div className="flex flex-wrap gap-2">
                <Badge className={getSeverityBadgeClass(selectedAlert.severity)}>
                  {severityLabels[selectedAlert.severity]}
                </Badge>
                <Badge variant="outline" className={getStatusBadgeClass(selectedAlert.status)}>
                  {statusLabels[selectedAlert.status]}
                </Badge>
              </div>
              
              <Separator />
              
              <div>
                <h4 className="mb-2 font-semibold">摘要</h4>
                <p className="text-sm text-muted-foreground">{selectedAlert.summary}</p>
              </div>
              
              <div className="grid gap-4 sm:grid-cols-2">
                <div>
                  <h4 className="mb-2 font-semibold">端點資訊</h4>
                  <div className="text-sm text-muted-foreground">
                    <p>名稱: {selectedAlert.agent_name}</p>
                    <p>IP: {selectedAlert.agent_ip}</p>
                  </div>
                </div>
                <div>
                  <h4 className="mb-2 font-semibold">時間</h4>
                  <p className="text-sm text-muted-foreground">
                    {format(new Date(selectedAlert.timestamp), "yyyy/MM/dd HH:mm:ss", { locale: zhTW })}
                  </p>
                </div>
              </div>
              
              <Separator />
              
              <div>
                <h4 className="mb-2 font-semibold">業務影響</h4>
                <p className="text-sm text-muted-foreground">{selectedAlert.business_impact}</p>
              </div>
              
              <div>
                <h4 className="mb-2 font-semibold">建議處理步驟</h4>
                <p className="whitespace-pre-line text-sm text-muted-foreground">
                  {selectedAlert.recommended_action}
                </p>
              </div>
              
              <Separator />
              
              <div className="flex flex-wrap gap-2">
                <Button onClick={() => handleStatusChange(selectedAlert.id, "acknowledged")}>
                  <CheckCircle2 data-icon="inline-start" />
                  正常操作
                </Button>
                <Button variant="secondary" onClick={() => handleStatusChange(selectedAlert.id, "resolved")}>
                  <CheckCircle2 data-icon="inline-start" />
                  已處理
                </Button>
                <Button variant="outline" onClick={() => handleStatusChange(selectedAlert.id, "false_positive")}>
                  <XCircle data-icon="inline-start" />
                  誤報
                </Button>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </>
  );
}

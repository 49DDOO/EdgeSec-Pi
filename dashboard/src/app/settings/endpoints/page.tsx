"use client";

import { useState } from "react";
import {
  Monitor,
  Plus,
  RefreshCw,
  Copy,
  CheckCircle2,
  XCircle,
  Clock,
  AlertTriangle,
  Info,
  Download,
  Laptop,
  Server,
  Terminal,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { ThemeToggle } from "@/components/dashboard/theme-toggle";
import { toast } from "sonner";

interface Endpoint {
  id: string;
  name: string;
  ip: string;
  os: string;
  status: "online" | "offline" | "warning";
  agentVersion: string;
  lastSeen: string;
  purpose: string;
}

const mockEndpoints: Endpoint[] = [
  {
    id: "1",
    name: "web-server-01",
    ip: "192.168.1.10",
    os: "Ubuntu 22.04",
    status: "online",
    agentVersion: "4.14.5",
    lastSeen: "1 分鐘前",
    purpose: "公司官網",
  },
  {
    id: "2",
    name: "db-finance-01",
    ip: "192.168.1.20",
    os: "CentOS 8",
    status: "online",
    agentVersion: "4.14.5",
    lastSeen: "2 分鐘前",
    purpose: "財務資料庫",
  },
  {
    id: "3",
    name: "file-server-01",
    ip: "192.168.1.30",
    os: "Windows Server 2019",
    status: "warning",
    agentVersion: "4.12.0",
    lastSeen: "15 分鐘前",
    purpose: "檔案伺服器",
  },
  {
    id: "4",
    name: "dev-workstation-01",
    ip: "192.168.1.100",
    os: "macOS Ventura",
    status: "offline",
    agentVersion: "4.14.5",
    lastSeen: "2 小時前",
    purpose: "開發用電腦",
  },
];

const installCommands = {
  linux: `curl -so wazuh-agent-4.14.5.deb https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.14.5-1_amd64.deb && sudo WAZUH_MANAGER='your-manager-ip' dpkg -i ./wazuh-agent-4.14.5.deb && sudo systemctl start wazuh-agent`,
  windows: `Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.5-1.msi -OutFile wazuh-agent.msi; msiexec.exe /i wazuh-agent.msi /q WAZUH_MANAGER="your-manager-ip"`,
  macos: `curl -so wazuh-agent-4.14.5.pkg https://packages.wazuh.com/4.x/macos/wazuh-agent-4.14.5-1.intel64.pkg && sudo WAZUH_MANAGER='your-manager-ip' installer -pkg ./wazuh-agent-4.14.5.pkg -target /`,
};

function StatusIcon({ status }: { status: Endpoint["status"] }) {
  switch (status) {
    case "online":
      return <CheckCircle2 className="size-4 text-green-500" />;
    case "offline":
      return <XCircle className="size-4 text-destructive" />;
    case "warning":
      return <AlertTriangle className="size-4 text-yellow-500" />;
  }
}

function StatusBadge({ status }: { status: Endpoint["status"] }) {
  switch (status) {
    case "online":
      return <Badge className="bg-green-500 text-white">連線中</Badge>;
    case "offline":
      return <Badge variant="destructive">離線</Badge>;
    case "warning":
      return <Badge className="bg-yellow-500 text-black">需注意</Badge>;
  }
}

function OsIcon({ os }: { os: string }) {
  const lower = os.toLowerCase();
  if (lower.includes("mac")) return <Laptop className="size-4" />;
  if (lower.includes("windows")) return <Monitor className="size-4" />;
  return <Server className="size-4" />;
}

export default function EndpointsPage() {
  const [endpoints] = useState<Endpoint[]>(mockEndpoints);
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedOs, setSelectedOs] = useState<"linux" | "windows" | "macos">("linux");

  const filteredEndpoints = endpoints.filter(
    (ep) =>
      ep.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      ep.purpose.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const stats = {
    total: endpoints.length,
    online: endpoints.filter((e) => e.status === "online").length,
    offline: endpoints.filter((e) => e.status === "offline").length,
    warning: endpoints.filter((e) => e.status === "warning").length,
  };

  const handleCopyCommand = () => {
    navigator.clipboard.writeText(installCommands[selectedOs]);
    toast.success("已複製到剪貼簿");
  };

  const handleRefresh = () => {
    toast.success("正在重新整理設備狀態...");
  };

  return (
    <div className="flex h-full flex-col">
      {/* Page Header */}
      <header className="flex items-center justify-between border-b border-border bg-card px-6 py-4">
        <div className="flex items-center gap-3">
          <div className="flex size-10 items-center justify-center rounded-lg bg-primary/10">
            <Monitor className="size-5 text-primary" />
          </div>
          <div>
            <h1 className="text-xl font-semibold">設備管理</h1>
            <p className="text-sm text-muted-foreground">
              查看與管理所有受監控的電腦和伺服器
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" onClick={handleRefresh}>
            <RefreshCw data-icon="inline-start" />
            重新整理
          </Button>
          <Dialog>
            <DialogTrigger asChild>
              <Button>
                <Plus data-icon="inline-start" />
                新增設備
              </Button>
            </DialogTrigger>
            <DialogContent className="max-w-2xl">
              <DialogHeader>
                <DialogTitle>新增監控設備</DialogTitle>
                <DialogDescription>
                  在您的電腦或伺服器上執行以下指令，即可開始監控
                </DialogDescription>
              </DialogHeader>
              <div className="space-y-4">
                <div className="flex gap-2">
                  <Button
                    variant={selectedOs === "linux" ? "default" : "outline"}
                    onClick={() => setSelectedOs("linux")}
                    className="flex-1"
                  >
                    <Server data-icon="inline-start" />
                    Linux
                  </Button>
                  <Button
                    variant={selectedOs === "windows" ? "default" : "outline"}
                    onClick={() => setSelectedOs("windows")}
                    className="flex-1"
                  >
                    <Monitor data-icon="inline-start" />
                    Windows
                  </Button>
                  <Button
                    variant={selectedOs === "macos" ? "default" : "outline"}
                    onClick={() => setSelectedOs("macos")}
                    className="flex-1"
                  >
                    <Laptop data-icon="inline-start" />
                    macOS
                  </Button>
                </div>
                <div className="relative">
                  <pre className="overflow-x-auto rounded-lg bg-muted p-4 text-xs">
                    <code>{installCommands[selectedOs]}</code>
                  </pre>
                  <Button
                    variant="secondary"
                    size="sm"
                    className="absolute right-2 top-2"
                    onClick={handleCopyCommand}
                  >
                    <Copy data-icon="inline-start" />
                    複製
                  </Button>
                </div>
                <div className="flex items-start gap-2 rounded-lg bg-blue-50 p-3 dark:bg-blue-950/30">
                  <Info className="mt-0.5 size-4 shrink-0 text-blue-600 dark:text-blue-400" />
                  <p className="text-sm text-blue-800 dark:text-blue-200">
                    請將指令中的 <code className="rounded bg-blue-100 px-1 dark:bg-blue-900">your-manager-ip</code> 替換為您的 Wazuh Manager IP 位址。
                    安裝完成後，設備會在幾分鐘內出現在清單中。
                  </p>
                </div>
              </div>
            </DialogContent>
          </Dialog>
          <ThemeToggle />
        </div>
      </header>

      {/* Main Content */}
      <main className="flex-1 overflow-auto p-6">
        <div className="mx-auto max-w-6xl space-y-6">
          {/* Stats */}
          <div className="grid gap-4 sm:grid-cols-4">
            <Card>
              <CardContent className="flex items-center gap-4 p-4">
                <div className="flex size-12 items-center justify-center rounded-lg bg-muted">
                  <Monitor className="size-6" />
                </div>
                <div>
                  <p className="text-2xl font-bold">{stats.total}</p>
                  <p className="text-sm text-muted-foreground">全部設備</p>
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="flex items-center gap-4 p-4">
                <div className="flex size-12 items-center justify-center rounded-lg bg-green-100 dark:bg-green-950">
                  <CheckCircle2 className="size-6 text-green-600 dark:text-green-400" />
                </div>
                <div>
                  <p className="text-2xl font-bold text-green-600 dark:text-green-400">{stats.online}</p>
                  <p className="text-sm text-muted-foreground">連線中</p>
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="flex items-center gap-4 p-4">
                <div className="flex size-12 items-center justify-center rounded-lg bg-yellow-100 dark:bg-yellow-950">
                  <AlertTriangle className="size-6 text-yellow-600 dark:text-yellow-400" />
                </div>
                <div>
                  <p className="text-2xl font-bold text-yellow-600 dark:text-yellow-400">{stats.warning}</p>
                  <p className="text-sm text-muted-foreground">需注意</p>
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="flex items-center gap-4 p-4">
                <div className="flex size-12 items-center justify-center rounded-lg bg-red-100 dark:bg-red-950">
                  <XCircle className="size-6 text-red-600 dark:text-red-400" />
                </div>
                <div>
                  <p className="text-2xl font-bold text-red-600 dark:text-red-400">{stats.offline}</p>
                  <p className="text-sm text-muted-foreground">離線</p>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Endpoints Table */}
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle>設備清單</CardTitle>
                  <CardDescription>
                    所有已安裝監控程式的電腦和伺服器
                  </CardDescription>
                </div>
                <Input
                  placeholder="搜尋設備名稱或用途..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="w-64"
                />
              </div>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>狀態</TableHead>
                    <TableHead>設備名稱</TableHead>
                    <TableHead>用途</TableHead>
                    <TableHead>作業系統</TableHead>
                    <TableHead>IP 位址</TableHead>
                    <TableHead>Agent 版本</TableHead>
                    <TableHead>最後連線</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredEndpoints.map((endpoint) => (
                    <TableRow key={endpoint.id}>
                      <TableCell>
                        <StatusBadge status={endpoint.status} />
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <OsIcon os={endpoint.os} />
                          <span className="font-mono text-sm">{endpoint.name}</span>
                        </div>
                      </TableCell>
                      <TableCell className="text-muted-foreground">
                        {endpoint.purpose}
                      </TableCell>
                      <TableCell>{endpoint.os}</TableCell>
                      <TableCell className="font-mono text-sm">
                        {endpoint.ip}
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline">v{endpoint.agentVersion}</Badge>
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-1 text-muted-foreground">
                          <Clock className="size-3" />
                          {endpoint.lastSeen}
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
              {filteredEndpoints.length === 0 && (
                <div className="py-8 text-center text-muted-foreground">
                  找不到符合條件的設備
                </div>
              )}
            </CardContent>
          </Card>

          {/* Help Section */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Terminal className="size-5" />
                需要協助？
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid gap-4 sm:grid-cols-2">
                <div className="rounded-lg border border-border p-4">
                  <h4 className="mb-2 font-medium">設備顯示離線怎麼辦？</h4>
                  <p className="text-sm text-muted-foreground">
                    1. 確認該電腦是否開機並連上網路<br />
                    2. 檢查 Wazuh Agent 服務是否正常運作<br />
                    3. 確認防火牆是否允許連線到 Manager
                  </p>
                </div>
                <div className="rounded-lg border border-border p-4">
                  <h4 className="mb-2 font-medium">Agent 版本過舊？</h4>
                  <p className="text-sm text-muted-foreground">
                    建議將 Agent 更新到最新版本以獲得最佳防護。
                    可以在該設備上重新執行安裝指令來更新。
                  </p>
                </div>
              </div>
              <div className="flex items-center justify-between rounded-lg bg-muted/50 p-4">
                <div>
                  <p className="font-medium">下載完整安裝指南</p>
                  <p className="text-sm text-muted-foreground">
                    包含各作業系統的詳細安裝步驟與疑難排解
                  </p>
                </div>
                <Button variant="outline">
                  <Download data-icon="inline-start" />
                  下載 PDF
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      </main>
    </div>
  );
}

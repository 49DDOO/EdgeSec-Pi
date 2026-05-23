"use client";

import { useEffect, useMemo, useState } from "react";
import {
  CheckCircle2,
  Clock,
  Copy,
  Download,
  Laptop,
  Monitor,
  RefreshCw,
  Server,
  Wrench,
  XCircle,
} from "lucide-react";
import { toast } from "sonner";
import { ThemeToggle } from "@/components/dashboard/theme-toggle";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogDescription,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { fetchDashboardSummary, updateEndpointBusinessContext } from "@/lib/api";
import type { Endpoint, EndpointBusinessContext, EndpointStatus } from "@/lib/types";

type OsKind = "macos" | "windows" | "debian" | "rpm";

const osOptions: Array<{ key: OsKind; label: string; description: string }> = [
  { key: "macos", label: "macOS", description: "Apple silicon / Intel" },
  { key: "windows", label: "Windows", description: "MSI 安裝檔" },
  { key: "debian", label: "Linux DEB", description: "Ubuntu / Debian" },
  { key: "rpm", label: "Linux RPM", description: "RHEL / CentOS / Amazon Linux" },
];

const defaultContext: Omit<EndpointBusinessContext, "configured"> = {
  role: "",
  owner: "",
  criticality: "medium",
  business_hours: "Mon-Fri 09:00-19:00 Asia/Taipei",
  pci_scope: false,
  notes: "",
};

function formatDateTime(value: string) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value || "未知";
  return new Intl.DateTimeFormat("zh-TW", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
}

function StatusBadge({ status }: { status: EndpointStatus }) {
  if (status === "online") {
    return <Badge className="bg-emerald-600 text-white hover:bg-emerald-600">在線</Badge>;
  }
  if (status === "offline") {
    return <Badge variant="destructive">離線</Badge>;
  }
  return <Badge variant="secondary">需注意</Badge>;
}

function SecurityScore({
  endpoint,
  onOpen,
}: {
  endpoint: Endpoint;
  onOpen: (endpoint: Endpoint) => void;
}) {
  if (endpoint.sca_score == null) {
    return (
      <button
        type="button"
        onClick={() => onOpen(endpoint)}
        className="space-y-1 text-left"
      >
        <div className="text-sm font-medium text-muted-foreground">尚未取得</div>
        <div className="text-xs text-muted-foreground">查看原因</div>
      </button>
    );
  }
  const color =
    endpoint.sca_score >= 80
      ? "text-emerald-600"
      : endpoint.sca_score >= 60
        ? "text-amber-600"
        : "text-red-600";
  return (
    <button
      type="button"
      onClick={() => onOpen(endpoint)}
      className="space-y-1 rounded-md text-left outline-none transition-colors hover:bg-muted focus-visible:ring-2 focus-visible:ring-ring"
      aria-label={`查看 ${endpoint.name} 安全設定分數原因`}
    >
      <div className={`text-lg font-semibold ${color}`}>{endpoint.sca_score}</div>
      <div className="text-xs text-muted-foreground">
        {endpoint.sca?.failed || endpoint.sca?.total
          ? `${endpoint.sca.failed ?? 0} 未通過 / ${endpoint.sca.total ?? 0} 項`
          : "點開看原因"}
      </div>
    </button>
  );
}

function SecurityScoreDialog({
  endpoint,
  onClose,
}: {
  endpoint: Endpoint | null;
  onClose: () => void;
}) {
  const score = endpoint?.sca_score;
  const failed = endpoint?.sca?.failed ?? 0;
  const passed = endpoint?.sca?.passed ?? 0;
  const total = endpoint?.sca?.total ?? 0;
  const invalid = endpoint?.sca?.invalid ?? 0;
  const plainFailedChecks = endpoint?.sca?.plain_failed_checks ?? [];
  const failedChecks = endpoint?.sca?.failed_checks ?? [];
  const scoreText = score == null ? "尚未取得" : `${score} / 100`;
  const needsAttention = score != null && score < 80;
  const reason =
    score == null
      ? "Wazuh 還沒有回報這台電腦的安全設定檢查結果。通常是 Agent 剛安裝、尚未完成掃描，或 Manager 尚未同步。"
      : failed > 0
        ? `這台電腦有 ${failed} 項安全設定沒有通過，所以分數不是滿分。`
        : "目前沒有未通過項目，分數偏低時請確認是否有部分檢查尚未完成。";

  return (
    <Dialog open={Boolean(endpoint)} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle>安全設定分數</DialogTitle>
          <DialogDescription>
            這是電腦設定健檢，不是入侵警報。分數低代表有設定需要請 IT 補強。
          </DialogDescription>
        </DialogHeader>

        {endpoint && (
          <div className="space-y-5">
            <div className="rounded-lg border bg-muted/40 p-4">
              <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
                <div>
                  <div className="text-sm text-muted-foreground">{endpoint.name}</div>
                  <div className="mt-1 text-4xl font-semibold">{scoreText}</div>
                </div>
                <Badge variant={needsAttention ? "destructive" : "outline"}>
                  {needsAttention ? "需要 IT 補強" : "目前可接受"}
                </Badge>
              </div>
              <p className="mt-3 text-sm text-muted-foreground">{reason}</p>
            </div>

            <div className="grid gap-3 sm:grid-cols-4">
              <div className="rounded-lg border p-3">
                <div className="text-xs text-muted-foreground">通過</div>
                <div className="text-2xl font-semibold text-emerald-600">{passed}</div>
              </div>
              <div className="rounded-lg border p-3">
                <div className="text-xs text-muted-foreground">未通過</div>
                <div className="text-2xl font-semibold text-red-600">{failed}</div>
              </div>
              <div className="rounded-lg border p-3">
                <div className="text-xs text-muted-foreground">無法判斷</div>
                <div className="text-2xl font-semibold text-muted-foreground">{invalid}</div>
              </div>
              <div className="rounded-lg border p-3">
                <div className="text-xs text-muted-foreground">總檢查項</div>
                <div className="text-2xl font-semibold">{total || "-"}</div>
              </div>
            </div>

            <div className="rounded-lg border p-4">
              <div className="text-base font-semibold">先處理這幾項</div>
              <p className="mt-1 text-sm text-muted-foreground">
                來源是 Wazuh 的未通過檢查；有補強步驟時會直接附在項目下方。
              </p>
              <div className="mt-4 space-y-2">
                {plainFailedChecks.length ? plainFailedChecks.slice(0, 3).map((check) => (
                  <div key={check.source_title || check.title_zh} className="rounded-lg border bg-background p-3">
                    <div className="flex gap-3">
                      <div className="mt-1 size-2 shrink-0 rounded-full bg-amber-500" />
                      <div className="space-y-1">
                        <div className="font-medium">{check.title_zh}</div>
                        <div className="text-sm text-muted-foreground">{check.action_zh}</div>
                        <div className="text-xs text-muted-foreground">
                          {check.source === "llm_from_wazuh_sca" ? "本機 LLM 摘要" : "Wazuh 原始項目"}
                        </div>
                        {check.source_remediation ? (
                          <details className="text-xs text-muted-foreground">
                            <summary className="cursor-pointer font-medium text-foreground">Wazuh 補強步驟</summary>
                            <div className="mt-2 whitespace-pre-wrap rounded-md bg-muted p-2 leading-relaxed">
                              {check.source_remediation}
                            </div>
                          </details>
                        ) : null}
                        <details className="text-xs text-muted-foreground">
                          <summary className="cursor-pointer">原始 Wazuh 檢查名稱</summary>
                          <div className="mt-1 break-words">{check.source_title}</div>
                        </details>
                      </div>
                    </div>
                  </div>
                )) : failedChecks.length ? failedChecks.slice(0, 3).map((check) => (
                  <div key={check.id || check.title} className="rounded-lg border bg-background p-3">
                    <div className="flex gap-3">
                      <div className="mt-1 size-2 shrink-0 rounded-full bg-amber-500" />
                      <div className="space-y-1">
                        <div className="font-medium">{check.title || "Wazuh 安全設定檢查未通過"}</div>
                        <div className="text-sm text-muted-foreground">
                          {check.remediation
                            ? "請 IT 依下方 Wazuh 補強步驟處理；若是公司允許的例外，請留下紀錄。"
                            : "請 IT 查看 Wazuh 原始檢查項目；若是公司允許的例外，請留下紀錄。"}
                        </div>
                        <div className="text-xs text-muted-foreground">Wazuh 原始項目</div>
                        {check.remediation ? (
                          <details className="text-xs text-muted-foreground">
                            <summary className="cursor-pointer font-medium text-foreground">Wazuh 補強步驟</summary>
                            <div className="mt-2 whitespace-pre-wrap rounded-md bg-muted p-2 leading-relaxed">
                              {check.remediation}
                            </div>
                          </details>
                        ) : null}
                      </div>
                    </div>
                  </div>
                )) : (
                  <div className="rounded-lg border bg-background p-3 text-sm text-muted-foreground">
                    目前只取得分數，尚未取得未通過清單。請 IT 到 Wazuh Dashboard 查看這台電腦的安全設定檢查。
                  </div>
                )}
              </div>
            </div>

            <div className="space-y-3 rounded-lg border p-4 text-sm">
              <div className="grid gap-1 sm:grid-cols-[120px_1fr]">
                <div className="text-muted-foreground">檢查基準</div>
                <div className="font-medium">{endpoint.sca?.policy || "尚未取得"}</div>
              </div>
              <div className="grid gap-1 sm:grid-cols-[120px_1fr]">
                <div className="text-muted-foreground">上次掃描</div>
                <div>{endpoint.sca?.last_scan ? formatDateTime(endpoint.sca.last_scan) : "尚未取得"}</div>
              </div>
              <div className="grid gap-1 sm:grid-cols-[120px_1fr]">
                <div className="text-muted-foreground">建議動作</div>
                <div>
                  請把「先處理這幾項」交給 IT；處理後重新掃描，確認分數有上升。
                </div>
              </div>
            </div>
          </div>
        )}

        <DialogFooter>
          <Button variant="outline" onClick={onClose}>關閉</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function OsIcon({ os }: { os: string }) {
  const lower = os.toLowerCase();
  if (lower.includes("mac")) return <Laptop className="size-4" />;
  if (lower.includes("windows")) return <Monitor className="size-4" />;
  return <Server className="size-4" />;
}

function managerHostFromBrowser() {
  const apiBase = process.env.NEXT_PUBLIC_BRIDGE_API_BASE || "";
  try {
    if (apiBase) return new URL(apiBase).hostname;
  } catch {
    // Fall through to browser location.
  }
  if (typeof window !== "undefined") return window.location.hostname;
  return "192.168.x.x";
}

function installCommand(os: OsKind, managerHost: string) {
  const host = managerHost.trim() || "192.168.x.x";
  if (os === "windows") {
    return `Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.5-1.msi -OutFile wazuh-agent.msi\nmsiexec.exe /i wazuh-agent.msi /q WAZUH_MANAGER="${host}"`;
  }
  if (os === "macos") {
    return `curl -so wazuh-agent-4.14.5.pkg https://packages.wazuh.com/4.x/macos/wazuh-agent-4.14.5-1.intel64.pkg\nsudo WAZUH_MANAGER='${host}' installer -pkg ./wazuh-agent-4.14.5.pkg -target /\nsudo /Library/Ossec/bin/wazuh-control start`;
  }
  if (os === "rpm") {
    return `curl -so wazuh-agent-4.14.5.rpm https://packages.wazuh.com/4.x/yum/wazuh-agent-4.14.5-1.x86_64.rpm\nsudo WAZUH_MANAGER='${host}' rpm -ihv ./wazuh-agent-4.14.5.rpm\nsudo systemctl enable --now wazuh-agent`;
  }
  return `curl -so wazuh-agent-4.14.5.deb https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.14.5-1_amd64.deb\nsudo WAZUH_MANAGER='${host}' dpkg -i ./wazuh-agent-4.14.5.deb\nsudo systemctl enable --now wazuh-agent`;
}

export default function EndpointsPage() {
  const [endpoints, setEndpoints] = useState<Endpoint[]>([]);
  const [searchTerm, setSearchTerm] = useState("");
  const [loading, setLoading] = useState(true);
  const [managerHost, setManagerHost] = useState(() => managerHostFromBrowser());
  const [selectedOs, setSelectedOs] = useState<OsKind>("macos");
  const [editing, setEditing] = useState<Endpoint | null>(null);
  const [securityDetails, setSecurityDetails] = useState<Endpoint | null>(null);
  const [draft, setDraft] = useState(defaultContext);
  const [saving, setSaving] = useState(false);

  async function loadEndpoints() {
    setLoading(true);
    try {
      const summary = await fetchDashboardSummary();
      setEndpoints(summary.endpoints);
      if (summary.install?.manager_host) {
        setManagerHost(summary.install.manager_host);
      }
      if (summary.demo) {
        toast.warning("目前顯示示範資料", { description: summary.error });
      }
    } catch (error) {
      toast.error("讀取端點失敗", {
        description: error instanceof Error ? error.message : String(error),
      });
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    fetchDashboardSummary()
      .then((summary) => {
        setEndpoints(summary.endpoints);
        if (summary.install?.manager_host) {
          setManagerHost(summary.install.manager_host);
        }
        if (summary.demo) {
          toast.warning("目前顯示示範資料", { description: summary.error });
        }
      })
      .catch((error) => {
        toast.error("讀取端點失敗", {
          description: error instanceof Error ? error.message : String(error),
        });
      })
      .finally(() => setLoading(false));
  }, []);

  const filteredEndpoints = endpoints.filter((endpoint) => {
    const query = searchTerm.toLowerCase();
    return (
      endpoint.name.toLowerCase().includes(query) ||
      endpoint.ip.toLowerCase().includes(query) ||
      endpoint.purpose.toLowerCase().includes(query)
    );
  });

  const stats = useMemo(() => ({
    total: endpoints.length,
    online: endpoints.filter((endpoint) => endpoint.status === "online").length,
    offline: endpoints.filter((endpoint) => endpoint.status === "offline").length,
    missingContext: endpoints.filter((endpoint) => !endpoint.business_context?.configured).length,
  }), [endpoints]);

  function openBusinessDialog(endpoint: Endpoint) {
    const context = endpoint.business_context;
    setEditing(endpoint);
    setDraft({
      role: context?.role || "",
      owner: context?.owner || "",
      criticality: context?.criticality || "medium",
      business_hours: context?.business_hours || "Mon-Fri 09:00-19:00 Asia/Taipei",
      pci_scope: Boolean(context?.pci_scope),
      notes: context?.notes || "",
    });
  }

  async function saveBusinessContext() {
    if (!editing) return;
    setSaving(true);
    try {
      await updateEndpointBusinessContext(editing.name, draft);
      toast.success("端點業務背景已儲存");
      setEditing(null);
      await loadEndpoints();
    } catch (error) {
      toast.error("儲存失敗", {
        description: error instanceof Error ? error.message : String(error),
      });
    } finally {
      setSaving(false);
    }
  }

  async function copyInstallCommand() {
    await navigator.clipboard.writeText(installCommand(selectedOs, managerHost));
    toast.success("安裝指令已複製");
  }

  return (
    <div className="flex h-full flex-col">
      <header className="flex items-center justify-between border-b border-border bg-card px-6 py-4">
        <div className="flex items-center gap-3">
          <div className="flex size-10 items-center justify-center rounded-lg bg-primary/10">
            <Monitor className="size-5 text-primary" />
          </div>
          <div>
            <h1 className="text-xl font-semibold">電腦端點</h1>
            <p className="text-sm text-muted-foreground">
              查看受監控電腦，補齊業務用途，下載 Agent 安裝方式
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" onClick={loadEndpoints} disabled={loading}>
            <RefreshCw data-icon="inline-start" />
            重新整理
          </Button>
          <ThemeToggle />
        </div>
      </header>

      <main className="flex-1 overflow-auto p-6">
        <div className="mx-auto max-w-6xl space-y-6">
          <div className="grid gap-4 sm:grid-cols-4">
            <Card>
              <CardContent className="flex items-center gap-4 p-4">
                <Monitor className="size-8 text-muted-foreground" />
                <div>
                  <p className="text-2xl font-bold">{stats.total}</p>
                  <p className="text-sm text-muted-foreground">端點總數</p>
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="flex items-center gap-4 p-4">
                <CheckCircle2 className="size-8 text-emerald-600" />
                <div>
                  <p className="text-2xl font-bold">{stats.online}</p>
                  <p className="text-sm text-muted-foreground">在線</p>
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="flex items-center gap-4 p-4">
                <XCircle className="size-8 text-destructive" />
                <div>
                  <p className="text-2xl font-bold">{stats.offline}</p>
                  <p className="text-sm text-muted-foreground">離線</p>
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="flex items-center gap-4 p-4">
                <Wrench className="size-8 text-amber-600" />
                <div>
                  <p className="text-2xl font-bold">{stats.missingContext}</p>
                  <p className="text-sm text-muted-foreground">待補業務背景</p>
                </div>
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader>
              <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                <div>
                  <CardTitle>安裝 Agent</CardTitle>
                  <CardDescription>
                    在要監控的電腦上執行安裝指令；Manager 位址請用內網可連到這台主機的 IP。
                  </CardDescription>
                </div>
                <div className="flex flex-wrap gap-2">
                  {osOptions.map((option) => (
                    <Button
                      key={option.key}
                      variant={selectedOs === option.key ? "default" : "outline"}
                      onClick={() => setSelectedOs(option.key)}
                    >
                      {option.label}
                    </Button>
                  ))}
                </div>
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid gap-4 sm:grid-cols-[280px_1fr]">
                <div className="space-y-2">
                  <label className="text-sm font-medium">Manager 位址</label>
                  <Input value={managerHost} onChange={(event) => setManagerHost(event.target.value)} />
                  <p className="text-xs text-muted-foreground">
                    例如：192.168.50.177。不要填 127.0.0.1，其他電腦會連不到。
                  </p>
                </div>
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <p className="text-sm font-medium">
                      {osOptions.find((option) => option.key === selectedOs)?.description}
                    </p>
                    <Button variant="outline" size="sm" onClick={copyInstallCommand}>
                      <Copy data-icon="inline-start" />
                      複製
                    </Button>
                  </div>
                  <pre className="overflow-x-auto rounded-lg border border-border bg-muted p-4 text-xs">
                    <code>{installCommand(selectedOs, managerHost)}</code>
                  </pre>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
                <div>
                  <CardTitle>端點清單</CardTitle>
                  <CardDescription>
                    每台端點顯示監控狀態、Agent 版本、作業系統與業務背景。
                  </CardDescription>
                </div>
                <Input
                  placeholder="搜尋電腦名稱、IP 或用途..."
                  value={searchTerm}
                  onChange={(event) => setSearchTerm(event.target.value)}
                  className="md:w-72"
                />
              </div>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>狀態</TableHead>
                    <TableHead>電腦</TableHead>
                    <TableHead>用途</TableHead>
                    <TableHead>作業系統</TableHead>
                    <TableHead>Agent</TableHead>
                    <TableHead>安全設定</TableHead>
                    <TableHead className="text-right">操作</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredEndpoints.map((endpoint) => (
                    <TableRow key={endpoint.id || endpoint.name}>
                      <TableCell><StatusBadge status={endpoint.status} /></TableCell>
                      <TableCell>
                        <div className="space-y-1">
                          <div className="flex items-center gap-2 font-medium">
                            <OsIcon os={endpoint.os} />
                            {endpoint.name}
                          </div>
                          <div className="text-xs text-muted-foreground">
                            {endpoint.ip || "IP 未回報"}
                            {endpoint.ip_is_loopback ? "（Agent 尚未回報內網位址）" : ""}
                          </div>
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="space-y-1">
                          <div className="font-medium">
                            {endpoint.business_context?.role || "尚未設定"}
                          </div>
                          <div className="text-xs text-muted-foreground">
                            {endpoint.business_context?.owner
                              ? `負責人：${endpoint.business_context.owner}`
                              : "補上後，通知會說明影響的人或流程"}
                          </div>
                        </div>
                      </TableCell>
                      <TableCell>{endpoint.os || "unknown"}</TableCell>
                      <TableCell>
                        <div className="space-y-1">
                          <Badge variant="outline">{endpoint.version || "未知"}</Badge>
                          <div className="flex items-center gap-1 text-xs text-muted-foreground">
                            <Clock className="size-3" />
                            {formatDateTime(endpoint.last_sync)}
                          </div>
                        </div>
                      </TableCell>
                      <TableCell>
                        <SecurityScore endpoint={endpoint} onOpen={setSecurityDetails} />
                      </TableCell>
                      <TableCell className="text-right">
                        <Button variant="outline" onClick={() => openBusinessDialog(endpoint)}>
                          {endpoint.business_context?.configured ? "編輯業務背景" : "設定業務背景"}
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
              {!filteredEndpoints.length && (
                <div className="py-10 text-center text-sm text-muted-foreground">
                  {loading ? "讀取端點中..." : "找不到符合條件的端點"}
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Download className="size-5" />
                端點看不到時
              </CardTitle>
              <CardDescription>
                先確認 Agent 已啟動、Manager 位址不是 127.0.0.1，並確認 1514/1515 連線正常。
              </CardDescription>
            </CardHeader>
          </Card>
        </div>
      </main>

      <Dialog open={Boolean(editing)} onOpenChange={(open) => !open && setEditing(null)}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>{editing?.name} 的業務背景</DialogTitle>
          </DialogHeader>
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <label className="text-sm font-medium">用途</label>
              <Input
                value={draft.role}
                onChange={(event) => setDraft({ ...draft, role: event.target.value })}
                placeholder="例：開發者、門市 POS、財務主機"
              />
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">負責人</label>
              <Input
                value={draft.owner}
                onChange={(event) => setDraft({ ...draft, owner: event.target.value })}
                placeholder="例：Peter、外包 IT、門市主管"
              />
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">重要程度</label>
              <Input
                value={draft.criticality}
                onChange={(event) => setDraft({ ...draft, criticality: event.target.value })}
                placeholder="low / medium / high / critical"
              />
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">使用時段</label>
              <Input
                value={draft.business_hours}
                onChange={(event) => setDraft({ ...draft, business_hours: event.target.value })}
                placeholder="Mon-Fri 09:00-19:00 Asia/Taipei"
              />
            </div>
            <label className="flex items-center gap-2 rounded-lg border border-border px-3 py-2 text-sm sm:col-span-2">
              <input
                type="checkbox"
                checked={draft.pci_scope}
                onChange={(event) => setDraft({ ...draft, pci_scope: event.target.checked })}
              />
              這台會處理信用卡或付款資料
            </label>
            <div className="space-y-2 sm:col-span-2">
              <label className="text-sm font-medium">補充說明</label>
              <Textarea
                value={draft.notes}
                onChange={(event) => setDraft({ ...draft, notes: event.target.value })}
                placeholder="例：只有設計師 Peter 會使用；若半夜登入請立即通知外包 IT。"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditing(null)}>取消</Button>
            <Button onClick={saveBusinessContext} disabled={saving}>
              {saving ? "儲存中..." : "儲存"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      <SecurityScoreDialog
        endpoint={securityDetails}
        onClose={() => setSecurityDetails(null)}
      />
    </div>
  );
}

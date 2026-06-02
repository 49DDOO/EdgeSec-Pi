"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  ArrowLeft,
  CheckCircle2,
  Cloud,
  Copy,
  Database,
  Globe,
  KeyRound,
  LockKeyhole,
  Save,
  Server,
  Shield,
  SlidersHorizontal,
  TestTube,
  Webhook,
} from "lucide-react";
import { toast } from "sonner";
import { PageHeader } from "@/components/dashboard/page-header";
import { Badge } from "@/components/ui/badge";
import { Button, buttonVariants } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import {
  fetchWazuhSettings,
  replayBuiltInTestAlert,
  saveWazuhSettings,
  testWazuhIndexer,
  testWazuhManager,
} from "@/lib/api";
import type { WazuhSettings } from "@/lib/types";
import { cn } from "@/lib/utils";

type WazuhDeploymentMode = WazuhSettings["WAZUH_DEPLOYMENT_MODE"];

type Draft = WazuhSettings & {
  clear_WAZUH_API_PASS: boolean;
  clear_WAZUH_INDEXER_PASS: boolean;
  clear_WEBHOOK_SECRET: boolean;
};

type SectionKey = "manager" | "indexer" | "public";

const deploymentOptions: Array<{
  mode: WazuhDeploymentMode;
  title: string;
  description: string;
  detail: string;
  icon: typeof Cloud;
}> = [
  {
    mode: "managed",
    title: "EdgeSec 代管 Wazuh",
    description: "最適合沒有 IT 團隊的中小企業。",
    detail: "正式產品由 EdgeSec 建立與維護 Wazuh，客戶只需要部署端點 Agent。",
    icon: Cloud,
  },
  {
    mode: "existing",
    title: "連接現有 Wazuh",
    description: "雲端 Wazuh 或自行架設都走這條。",
    detail: "輸入 Manager / Indexer 地址與憑證，EdgeSec-Pi 負責戰情中心、AI 判讀與通知。",
    icon: Server,
  },
  {
    mode: "local_lab",
    title: "本機快速體驗",
    description: "給 Demo、PoC、工程測試使用。",
    detail: "使用本 repo 的 Docker single-node Wazuh；不建議當正式客戶安裝路徑。",
    icon: TestTube,
  },
];

function draftFromSettings(settings: WazuhSettings): Draft {
  return {
    ...settings,
    WAZUH_API_PASS: "",
    WAZUH_INDEXER_PASS: "",
    WEBHOOK_SECRET: "",
    clear_WAZUH_API_PASS: false,
    clear_WAZUH_INDEXER_PASS: false,
    clear_WEBHOOK_SECRET: false,
  };
}

function SecretField({
  label,
  configured,
  preview,
  value,
  placeholder,
  clearLabel,
  clearChecked,
  onValueChange,
  onClearChange,
}: {
  label: string;
  configured?: boolean;
  preview?: string;
  value: string;
  placeholder: string;
  clearLabel: string;
  clearChecked: boolean;
  onValueChange: (value: string) => void;
  onClearChange: (value: boolean) => void;
}) {
  return (
    <div className="space-y-3 border-t pt-6">
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <LockKeyhole className="size-5 text-muted-foreground" />
          <label className="text-sm font-semibold">{label}</label>
        </div>
        <Badge variant={configured ? "secondary" : "outline"}>
          {configured ? `已設定${preview ? `：${preview}` : ""}` : "未設定"}
        </Badge>
      </div>
      <div className="relative">
        <KeyRound className="pointer-events-none absolute left-3 top-3 size-4 text-muted-foreground" />
        <Input
          className="h-10 pl-9 text-sm"
          type="password"
          value={value}
          onChange={(event) => onValueChange(event.target.value)}
          placeholder={placeholder}
        />
      </div>
      {configured && (
        <label className="inline-flex items-center gap-2 text-sm font-medium text-red-600">
          <input
            type="checkbox"
            checked={clearChecked}
            onChange={(event) => onClearChange(event.target.checked)}
          />
          {clearLabel}
        </label>
      )}
    </div>
  );
}

function TlsWarning({ enabled }: { enabled: boolean }) {
  if (enabled) return null;
  return (
    <div className="flex items-center gap-3 rounded-lg border border-amber-300 bg-amber-50 px-4 py-3 text-sm font-medium text-amber-800">
      <AlertTriangle className="size-4 shrink-0" />
      TLS 驗證已關閉。在正式環境中，這可能導致中間人攻擊風險。
    </div>
  );
}

export default function WazuhSettingsPage() {
  const [settings, setSettings] = useState<WazuhSettings | null>(null);
  const [draft, setDraft] = useState<Draft | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [testingManager, setTestingManager] = useState(false);
  const [testingIndexer, setTestingIndexer] = useState(false);
  const [sendingAlert, setSendingAlert] = useState(false);
  const [activeSection, setActiveSection] = useState<SectionKey>("manager");
  const [managerConnected, setManagerConnected] = useState(false);
  const [indexerConnected, setIndexerConnected] = useState(false);

  useEffect(() => {
    let active = true;
    fetchWazuhSettings()
      .then((next) => {
        if (!active) return;
        setSettings(next);
        setDraft(draftFromSettings(next));
      })
      .catch((error) => {
        if (!active) return;
        toast.error("讀取 Wazuh 連線設定失敗", {
          description: error instanceof Error ? error.message : String(error),
        });
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, []);

  function updateDraft<K extends keyof Draft>(key: K, value: Draft[K]) {
    setDraft((current) => (current ? { ...current, [key]: value } : current));
  }

  async function persistDraft(showToast = false) {
    if (!draft) return;
    setSaving(true);
    try {
      const next = await saveWazuhSettings(draft);
      setSettings(next);
      setDraft(draftFromSettings(next));
      setManagerConnected(false);
      setIndexerConnected(false);
      if (showToast) {
        toast.success(next.message || "Wazuh 連線設定已儲存");
      }
      return next;
    } catch (error) {
      toast.error("儲存 Wazuh 設定失敗", {
        description: error instanceof Error ? error.message : String(error),
      });
      return null;
    } finally {
      setSaving(false);
    }
  }

  async function handleSave() {
    await persistDraft(true);
  }

  async function handleTestManager() {
    setTestingManager(true);
    try {
      const saved = await persistDraft();
      if (!saved) return;
      const result = await testWazuhManager();
      setManagerConnected(true);
      toast.success(result.message || "Wazuh Manager 連線測試成功");
    } catch (error) {
      setManagerConnected(false);
      toast.error("Wazuh Manager 測試失敗", {
        description: error instanceof Error ? error.message : String(error),
      });
    } finally {
      setTestingManager(false);
    }
  }

  async function handleTestIndexer() {
    setTestingIndexer(true);
    try {
      const saved = await persistDraft();
      if (!saved) return;
      const result = await testWazuhIndexer();
      setIndexerConnected(true);
      toast.success(result.message || "Wazuh Indexer 連線測試成功");
    } catch (error) {
      setIndexerConnected(false);
      toast.error("Wazuh Indexer 測試失敗", {
        description: error instanceof Error ? error.message : String(error),
      });
    } finally {
      setTestingIndexer(false);
    }
  }

  async function handleSendBuiltInAlert() {
    setSendingAlert(true);
    try {
      const result = await replayBuiltInTestAlert();
      toast.success("內建測試事件已送出", {
        description: result.message,
      });
    } catch (error) {
      toast.error("送出內建測試事件失敗", {
        description: error instanceof Error ? error.message : String(error),
      });
    } finally {
      setSendingAlert(false);
    }
  }

  async function copyWebhookUrl() {
    const value = draft?.webhook_url || settings?.webhook_url || "/webhook";
    try {
      await navigator.clipboard.writeText(value);
      toast.success("Webhook URL 已複製");
    } catch {
      toast.error("無法複製 Webhook URL");
    }
  }

  const webhookUrl = draft?.webhook_url || settings?.webhook_url || "/webhook";
  const deploymentMode = draft?.WAZUH_DEPLOYMENT_MODE || "existing";
  const deploymentLabel = deploymentOptions.find((option) => option.mode === deploymentMode)?.title
    || settings?.WAZUH_DEPLOYMENT_LABEL_ZH
    || "連接現有 Wazuh";
  const isManagedMode = deploymentMode === "managed";
  const webhookNeedsSecret = Boolean(settings?.WEBHOOK_SECRET_configured || draft?.WEBHOOK_SECRET);
  const managerReady = Boolean(
    draft?.WAZUH_API_URL &&
    draft?.WAZUH_API_USER &&
    (draft?.WAZUH_API_PASS || settings?.WAZUH_API_PASS_configured)
  );
  const indexerReady = Boolean(
    draft?.WAZUH_INDEXER_URL &&
    draft?.WAZUH_INDEXER_USER &&
    (draft?.WAZUH_INDEXER_PASS || settings?.WAZUH_INDEXER_PASS_configured)
  );
  const activeTitle = useMemo(() => {
    if (activeSection === "manager") return "Wazuh Manager API";
    if (activeSection === "indexer") return "Wazuh Indexer";
    return "EdgeSec-Pi 公開入口";
  }, [activeSection]);

  return (
    <div className="flex h-full flex-col bg-background">
      <PageHeader
        icon={Shield}
        title="Wazuh Alert 來源設定"
        description="這裡只設定 Wazuh 連線；設定完成後回來源總覽按「檢查來源」。"
        actions={
          <Link
            className={buttonVariants({ variant: "outline", size: "sm" })}
            href="/settings/sources/wazuh"
          >
            <ArrowLeft data-icon="inline-start" />
            回 Wazuh 來源總覽
          </Link>
        }
      />

      <main className="flex-1 overflow-auto px-8 py-8">
        <div className="mx-auto max-w-7xl space-y-8">
          <section className="rounded-lg border bg-card p-6 shadow-sm">
            <div className="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
              <div>
                <h2 className="text-lg font-semibold">你要怎麼使用 Wazuh？</h2>
                <p className="mt-1 text-sm text-muted-foreground">
                  架構上 Wazuh Alert 是一個事件來源；代管、既有雲端、地端自架與本機體驗共用同一個來源邊界。
                </p>
              </div>
              <Badge variant="secondary">{deploymentLabel}</Badge>
            </div>
            <div className="mt-5 grid gap-3 lg:grid-cols-3">
              {deploymentOptions.map((option) => {
                const Icon = option.icon;
                const selected = deploymentMode === option.mode;
                return (
                  <button
                    key={option.mode}
                    type="button"
                    className={cn(
                      "rounded-lg border p-4 text-left transition hover:border-primary/50 hover:bg-muted/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
                      selected ? "border-primary bg-primary/5" : "border-border bg-background"
                    )}
                    onClick={() => updateDraft("WAZUH_DEPLOYMENT_MODE", option.mode)}
                    disabled={!draft}
                  >
                    <div className="flex items-start gap-3">
                      <div className={cn(
                        "flex size-10 shrink-0 items-center justify-center rounded-lg",
                        selected ? "bg-primary text-primary-foreground" : "bg-muted text-muted-foreground"
                      )}>
                        <Icon className="size-5" />
                      </div>
                      <div>
                        <div className="font-semibold">{option.title}</div>
                        <p className="mt-1 text-sm text-muted-foreground">{option.description}</p>
                      </div>
                    </div>
                    <p className="mt-3 text-sm leading-6 text-muted-foreground">{option.detail}</p>
                  </button>
                );
              })}
            </div>
          </section>

          {isManagedMode && (
            <Card className="border-blue-200 bg-blue-50/50 shadow-sm">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-blue-800">
                  <Cloud className="size-5" />
                  代管 Wazuh 開通流程
                </CardTitle>
                <CardDescription className="text-blue-900/70">
                  正式產品中，這裡應接 EdgeSec provisioning：建立租戶、產生端點部署資訊、由平台保存 Wazuh 連線憑證。
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-3 text-sm text-blue-900/80">
                <p>目前此版本尚未接雲端開通服務，所以不要求老闆輸入 Wazuh 主機地址或金鑰。</p>
                <p>若要立即測試，請切到「連接現有 Wazuh」或「本機快速體驗」。</p>
              </CardContent>
            </Card>
          )}

          {!isManagedMode && (
            <>
          <section className="rounded-lg border border-amber-300 bg-amber-50/50 p-8 shadow-sm">
            <div className="grid gap-6 lg:grid-cols-[1fr_auto] lg:items-center">
              <div className="flex gap-5">
                <Webhook className="mt-1 size-6 shrink-0 text-amber-600" />
                <div className="min-w-0 flex-1 space-y-4">
                  <div>
                    <h2 className="text-lg font-semibold text-amber-700">Webhook 接收 URL</h2>
                    <p className="mt-2 text-sm text-muted-foreground">
                      Wazuh Manager 的 custom integration 需要把事件 POST 到這個位置
                    </p>
                  </div>
                  <div className="flex flex-col gap-3 lg:flex-row">
                    <div className="min-w-0 flex-1 rounded-lg border bg-background px-4 py-3 font-mono text-sm">
                      {webhookUrl}
                    </div>
                    <Button type="button" variant="outline" onClick={() => void copyWebhookUrl()}>
                      <Copy data-icon="inline-start" />
                      複製
                    </Button>
                  </div>
                  {webhookNeedsSecret && (
                    <p className="text-sm text-muted-foreground">
                      需要 Header: <code className="rounded bg-muted px-1.5 py-0.5">Authorization: Bearer &lt;WEBHOOK_SECRET&gt;</code>
                    </p>
                  )}
                </div>
              </div>
              <Button
                type="button"
                variant="outline"
                onClick={() => void handleSendBuiltInAlert()}
                disabled={sendingAlert}
              >
                <TestTube data-icon="inline-start" />
                {sendingAlert ? "送出中..." : "測試事件流程"}
              </Button>
            </div>
          </section>

          <div className="grid grid-cols-3 rounded-lg bg-muted p-1">
            {[
              { key: "manager" as const, label: "Manager", icon: Server },
              { key: "indexer" as const, label: "Indexer", icon: Database },
              { key: "public" as const, label: "公開入口", icon: Globe },
            ].map((item) => {
              const Icon = item.icon;
              const active = activeSection === item.key;
              return (
                <button
                  key={item.key}
                  type="button"
                  className={cn(
                    "flex h-10 items-center justify-center gap-2 rounded-md text-sm font-semibold transition-colors",
                    active ? "bg-background text-foreground shadow-sm" : "text-muted-foreground hover:text-foreground"
                  )}
                  onClick={() => setActiveSection(item.key)}
                >
                  <Icon className="size-5" />
                  {item.label}
                </button>
              );
            })}
          </div>

          <Card className="rounded-lg shadow-sm">
            <CardHeader className="pb-6">
              <div className="flex items-start justify-between gap-4">
                <div className="flex items-start gap-4">
                  <SlidersHorizontal className="mt-1 size-6 text-muted-foreground" />
                  <div>
                    <CardTitle className="text-xl">{activeTitle}</CardTitle>
                    <CardDescription className="mt-2 text-sm">
                      {activeSection === "manager" && "用於 Agent 清單、安全設定分數、重新檢查與受控處置"}
                      {activeSection === "indexer" && "用於查詢 Wazuh Sample Data 與需要直接讀取索引的診斷功能"}
                      {activeSection === "public" && "Slack 深連結與 Wazuh webhook 文件會使用這個網址"}
                    </CardDescription>
                  </div>
                </div>
                {activeSection === "manager" && (
                  <Badge className={managerConnected ? "bg-emerald-100 text-emerald-700 hover:bg-emerald-100" : ""} variant={managerConnected ? "secondary" : settings?.WAZUH_API_PASS_configured ? "secondary" : "outline"}>
                    {managerConnected && <CheckCircle2 className="mr-1 size-3.5" />}
                    {managerConnected ? "已連線" : settings?.WAZUH_API_PASS_configured ? "已設定" : "未設定"}
                  </Badge>
                )}
                {activeSection === "indexer" && (
                  <Badge className={indexerConnected ? "bg-emerald-100 text-emerald-700 hover:bg-emerald-100" : ""} variant={indexerConnected ? "secondary" : settings?.WAZUH_INDEXER_PASS_configured ? "secondary" : "outline"}>
                    {indexerConnected && <CheckCircle2 className="mr-1 size-3.5" />}
                    {indexerConnected ? "已連線" : settings?.WAZUH_INDEXER_PASS_configured ? "已設定" : "未設定"}
                  </Badge>
                )}
                {activeSection === "public" && (
                  <Badge variant={settings?.WEBHOOK_SECRET_configured ? "secondary" : "outline"}>
                    {settings?.WEBHOOK_SECRET_configured ? "Secret 已設定" : "Secret 未設定"}
                  </Badge>
                )}
              </div>
            </CardHeader>

            <CardContent className="space-y-8">
              {activeSection === "manager" && (
                <>
                  {deploymentMode === "existing" && (
                    <div className="rounded-lg border bg-muted/30 px-4 py-3 text-sm text-muted-foreground">
                      雲端 Wazuh 或地端自架都使用這組設定；請輸入 Manager API 地址、使用者與密碼。
                    </div>
                  )}
                  {deploymentMode === "local_lab" && (
                    <div className="rounded-lg border bg-muted/30 px-4 py-3 text-sm text-muted-foreground">
                      本機體驗版通常使用 <code className="rounded bg-background px-1.5 py-0.5">https://localhost:55000</code>；正式客戶環境不建議走這條。
                    </div>
                  )}
                  <div className="grid gap-6 lg:grid-cols-2">
                    <div className="space-y-2">
                      <label className="text-sm font-semibold">Manager API URL</label>
                      <Input
                        className="h-10 text-sm"
                        value={draft?.WAZUH_API_URL || ""}
                        onChange={(event) => updateDraft("WAZUH_API_URL", event.target.value)}
                        placeholder="https://localhost:55000"
                      />
                    </div>
                    <div className="space-y-2">
                      <label className="text-sm font-semibold">API 使用者</label>
                      <Input
                        className="h-10 text-sm"
                        value={draft?.WAZUH_API_USER || ""}
                        onChange={(event) => updateDraft("WAZUH_API_USER", event.target.value)}
                        placeholder="wazuh-wui"
                      />
                    </div>
                  </div>

                  <SecretField
                    label="API 密碼"
                    configured={settings?.WAZUH_API_PASS_configured}
                    preview={settings?.WAZUH_API_PASS_preview}
                    value={draft?.WAZUH_API_PASS || ""}
                    placeholder={settings?.WAZUH_API_PASS_configured ? "輸入新密碼以更新" : "Wazuh API password"}
                    clearLabel="清除已儲存的密碼"
                    clearChecked={draft?.clear_WAZUH_API_PASS || false}
                    onValueChange={(value) => updateDraft("WAZUH_API_PASS", value)}
                    onClearChange={(value) => updateDraft("clear_WAZUH_API_PASS", value)}
                  />

                  <div className="space-y-5 border-t pt-8">
                    <label className="flex items-center justify-between gap-4 rounded-lg border p-4">
                      <span>
                        <span className="text-sm font-semibold">驗證 Manager TLS 憑證</span>
                        <span className="mt-1 block text-sm text-muted-foreground">
                          正式環境建議開啟，自簽測試環境可關閉
                        </span>
                      </span>
                      <Switch
                        checked={draft?.WAZUH_VERIFY_SSL ?? true}
                        onCheckedChange={(value) => updateDraft("WAZUH_VERIFY_SSL", Boolean(value))}
                        aria-label="驗證 Manager TLS 憑證"
                      />
                    </label>
                    <TlsWarning enabled={draft?.WAZUH_VERIFY_SSL ?? true} />
                  </div>

                  <div className="flex justify-end">
                    <Button
                      type="button"
                      variant="outline"
                      onClick={() => void handleTestManager()}
                      disabled={testingManager || loading || !managerReady}
                    >
                      <Server data-icon="inline-start" />
                      {testingManager ? "測試中..." : "測試連線"}
                    </Button>
                  </div>
                </>
              )}

              {activeSection === "indexer" && (
                <>
                  {deploymentMode === "existing" && (
                    <div className="rounded-lg border bg-muted/30 px-4 py-3 text-sm text-muted-foreground">
                      Indexer 用於查歷史事件與診斷資料；若是雲端 Wazuh，請填雲端提供的 Indexer/OpenSearch endpoint。
                    </div>
                  )}
                  {deploymentMode === "local_lab" && (
                    <div className="rounded-lg border bg-muted/30 px-4 py-3 text-sm text-muted-foreground">
                      本機體驗版通常使用 <code className="rounded bg-background px-1.5 py-0.5">https://localhost:9200</code>。
                    </div>
                  )}
                  <div className="grid gap-6 lg:grid-cols-2">
                    <div className="space-y-2">
                      <label className="text-sm font-semibold">Indexer URL</label>
                      <Input
                        className="h-10 text-sm"
                        value={draft?.WAZUH_INDEXER_URL || ""}
                        onChange={(event) => updateDraft("WAZUH_INDEXER_URL", event.target.value)}
                        placeholder="https://localhost:9200"
                      />
                    </div>
                    <div className="space-y-2">
                      <label className="text-sm font-semibold">Indexer 使用者</label>
                      <Input
                        className="h-10 text-sm"
                        value={draft?.WAZUH_INDEXER_USER || ""}
                        onChange={(event) => updateDraft("WAZUH_INDEXER_USER", event.target.value)}
                        placeholder="admin"
                      />
                    </div>
                  </div>

                  <SecretField
                    label="Indexer 密碼"
                    configured={settings?.WAZUH_INDEXER_PASS_configured}
                    preview={settings?.WAZUH_INDEXER_PASS_preview}
                    value={draft?.WAZUH_INDEXER_PASS || ""}
                    placeholder={settings?.WAZUH_INDEXER_PASS_configured ? "輸入新密碼以更新" : "Wazuh Indexer password"}
                    clearLabel="清除已儲存的密碼"
                    clearChecked={draft?.clear_WAZUH_INDEXER_PASS || false}
                    onValueChange={(value) => updateDraft("WAZUH_INDEXER_PASS", value)}
                    onClearChange={(value) => updateDraft("clear_WAZUH_INDEXER_PASS", value)}
                  />

                  <div className="space-y-5 border-t pt-8">
                    <label className="flex items-center justify-between gap-4 rounded-lg border p-4">
                      <span>
                        <span className="text-sm font-semibold">驗證 Indexer TLS 憑證</span>
                        <span className="mt-1 block text-sm text-muted-foreground">
                          官方 Docker sample 常用自簽憑證；正式環境建議開啟
                        </span>
                      </span>
                      <Switch
                        checked={draft?.WAZUH_INDEXER_VERIFY_SSL ?? false}
                        onCheckedChange={(value) => updateDraft("WAZUH_INDEXER_VERIFY_SSL", Boolean(value))}
                        aria-label="驗證 Indexer TLS 憑證"
                      />
                    </label>
                    <TlsWarning enabled={draft?.WAZUH_INDEXER_VERIFY_SSL ?? false} />
                  </div>

                  <div className="flex justify-end">
                    <Button
                      type="button"
                      variant="outline"
                      onClick={() => void handleTestIndexer()}
                      disabled={testingIndexer || loading || !indexerReady}
                    >
                      <Database data-icon="inline-start" />
                      {testingIndexer ? "測試中..." : "測試連線"}
                    </Button>
                  </div>
                </>
              )}

              {activeSection === "public" && (
                <>
                  <div className="grid gap-6 lg:grid-cols-2">
                    <div className="space-y-2">
                      <label className="text-sm font-semibold">Bridge Public URL</label>
                      <Input
                        className="h-10 text-sm"
                        value={draft?.BRIDGE_PUBLIC_URL || ""}
                        onChange={(event) => updateDraft("BRIDGE_PUBLIC_URL", event.target.value)}
                        placeholder="https://edgesec.example.com"
                      />
                    </div>
                    <div className="space-y-2">
                      <label className="text-sm font-semibold">目前 Webhook URL</label>
                      <div className="h-10 rounded-lg border bg-muted/30 px-3 py-2.5 font-mono text-sm">
                        {webhookUrl}
                      </div>
                    </div>
                  </div>

                  <SecretField
                    label="Webhook Secret"
                    configured={settings?.WEBHOOK_SECRET_configured}
                    preview={settings?.WEBHOOK_SECRET_preview}
                    value={draft?.WEBHOOK_SECRET || ""}
                    placeholder={settings?.WEBHOOK_SECRET_configured ? "輸入新 Secret 以更新" : "Authorization Bearer token"}
                    clearLabel="清除 Webhook Secret"
                    clearChecked={draft?.clear_WEBHOOK_SECRET || false}
                    onValueChange={(value) => updateDraft("WEBHOOK_SECRET", value)}
                    onClearChange={(value) => updateDraft("clear_WEBHOOK_SECRET", value)}
                  />
                </>
              )}
            </CardContent>
          </Card>

            </>
          )}

          <div className="sticky bottom-6 flex flex-wrap items-center justify-between gap-3 rounded-lg border bg-background/95 p-3 shadow-lg backdrop-blur">
            <Link
              className={buttonVariants({ variant: "outline" })}
              href="/settings/sources/wazuh"
            >
              <ArrowLeft data-icon="inline-start" />
              回來源總覽
            </Link>
            <Button
              type="button"
              className="h-11 rounded-lg px-5 text-sm"
              onClick={() => void handleSave()}
              disabled={!draft || saving || loading}
            >
              <Save data-icon="inline-start" />
              {saving ? "儲存中..." : "儲存 Wazuh 來源設定"}
            </Button>
          </div>
        </div>
      </main>
    </div>
  );
}

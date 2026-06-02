"use client";

import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  ArrowLeft,
  ArrowRight,
  BarChart3,
  CheckCircle2,
  Database,
  PlugZap,
  RefreshCw,
  Settings2,
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
import {
  fetchDashboardSummary,
  fetchDataSources,
  testDataSource,
  type DashboardSummary,
} from "@/lib/api";
import { normalizedSourceKey } from "@/lib/source-labels";
import {
  capabilityClass,
  sourceSettingsHref,
  sourceStatusView,
  splitCapabilities,
} from "@/lib/source-ui";
import type {
  DataSourceCapability,
  DataSourceItem,
  DataSourcesResponse,
} from "@/lib/types";
import { cn } from "@/lib/utils";

interface SourcePageData {
  sources: DataSourcesResponse;
  summary: DashboardSummary;
}

function routeSourceKey(value: string | string[] | undefined) {
  const raw = Array.isArray(value) ? value[0] : value;
  return decodeURIComponent(raw || "").trim();
}

function CapabilityPill({ capability }: { capability: DataSourceCapability }) {
  const stateLabel =
    capability.state === "ready"
      ? "已啟用"
      : capability.state === "planned"
        ? "預留"
        : "未啟用";
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-medium",
        capabilityClass(capability)
      )}
    >
      <span className="size-1.5 rounded-full bg-current opacity-60" />
      {capability.label_zh}
      <span className="text-[11px] opacity-70">({stateLabel})</span>
    </span>
  );
}

function readyCount(capabilities: DataSourceCapability[]) {
  return capabilities.filter((capability) => capability.state === "ready").length;
}

function formatLastEvent(timestamp?: string) {
  if (!timestamp) return "-";
  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) return "-";
  return date.toLocaleString("zh-TW", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function SourceMetric({
  label,
  value,
  detail,
}: {
  label: string;
  value: string | number;
  detail?: string;
}) {
  return (
    <div className="rounded-lg border bg-card p-4">
      <div className="text-xs font-medium text-muted-foreground">{label}</div>
      <div className="mt-2 text-2xl font-semibold">{value}</div>
      {detail && <div className="mt-1 text-xs text-muted-foreground">{detail}</div>}
    </div>
  );
}

function SourceActions({
  source,
  testing,
  onTest,
}: {
  source: DataSourceItem;
  testing: boolean;
  onTest: () => void;
}) {
  if (!source.test_supported) return null;
  return (
    <div className="flex flex-wrap justify-start gap-2 lg:justify-end">
      <Button
        type="button"
        variant="outline"
        size="sm"
        onClick={onTest}
        disabled={testing}
      >
        <PlugZap data-icon="inline-start" className={testing ? "animate-pulse" : ""} />
        檢查來源
      </Button>
    </div>
  );
}

function SourceRolePill({ label }: { label: string }) {
  return (
    <span className="inline-flex items-center rounded-full bg-muted px-2.5 py-1 text-xs font-medium text-muted-foreground">
      {label}
    </span>
  );
}

function WazuhConnectionGuide({
  settingsHref,
}: {
  settingsHref: string;
}) {
  return (
    <Card className="border-primary/20 bg-primary/5">
      <CardHeader>
        <CardTitle className="text-base">連上 Wazuh 其實只要 3 件事</CardTitle>
        <CardDescription>
          先讓 Wazuh Alert 能送進來；查證與隔離是加值能力，不需要一開始全部打開。
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid gap-3 md:grid-cols-3">
          <div className="rounded-lg border bg-card p-4">
            <div className="text-sm font-semibold">1. 填 Wazuh 位址</div>
            <p className="mt-2 text-sm leading-6 text-muted-foreground">
              輸入 Manager / Indexer 位址與 API 帳號或金鑰，讓 Agent 能查端點與證據。
            </p>
          </div>
          <div className="rounded-lg border bg-card p-4">
            <div className="text-sm font-semibold">2. 讓 Alert 送進來</div>
            <p className="mt-2 text-sm leading-6 text-muted-foreground">
              設好 Webhook Secret，Wazuh 發生事件時就會送到 EdgeSec-Pi。
            </p>
          </div>
          <div className="rounded-lg border bg-card p-4">
            <div className="text-sm font-semibold">3. 再開處置能力</div>
            <p className="mt-2 text-sm leading-6 text-muted-foreground">
              隔離或封鎖只在人工確認後執行；正式環境建議先測試再啟用。
            </p>
          </div>
        </div>
        <div className="flex flex-wrap gap-2">
          {settingsHref && (
            <Link className={buttonVariants({ size: "sm" })} href={settingsHref}>
              <Settings2 data-icon="inline-start" />
              開始連線設定
              <ArrowRight data-icon="inline-end" />
            </Link>
          )}
          <span className="self-center text-xs text-muted-foreground">
            設定完成後回到這頁按「檢查來源」確認。
          </span>
        </div>
      </CardContent>
    </Card>
  );
}

function FollowUpCard({ source }: { source: DataSourceItem }) {
  if (source.key !== "wazuh") {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-base">後續可做</CardTitle>
        </CardHeader>
        <CardContent className="text-sm text-muted-foreground">
          {source.next_step_zh}
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">連線確認後再做</CardTitle>
        <CardDescription>
          這些不是第一步；Wazuh 先連上、事件先送進來，再調整偵測與測試流程。
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-3 text-sm sm:grid-cols-3">
        <Link className="rounded-lg border p-3 hover:bg-muted/50" href="/settings/sources/wazuh/detections">
          <span className="font-semibold text-foreground">調整訊號類別</span>
          <span className="mt-1 block text-muted-foreground">控制 Wazuh 告警類型與噪音。</span>
        </Link>
        <Link className="rounded-lg border p-3 hover:bg-muted/50" href="/settings/testing">
          <span className="font-semibold text-foreground">跑流程測試</span>
          <span className="mt-1 block text-muted-foreground">確認事件、AI、通知與查證都通。</span>
        </Link>
        <Link className="rounded-lg border p-3 hover:bg-muted/50" href="/settings/setup">
          <span className="font-semibold text-foreground">看完整首次設定</span>
          <span className="mt-1 block text-muted-foreground">從資料來源到通知一次檢查。</span>
        </Link>
      </CardContent>
    </Card>
  );
}

export default function SourceDetailPage() {
  const params = useParams();
  const router = useRouter();
  const sourceKey = routeSourceKey(params.source);
  const [data, setData] = useState<SourcePageData | null>(null);
  const [loading, setLoading] = useState(true);
  const [testing, setTesting] = useState(false);

  const loadData = useCallback(async (showToast = false) => {
    setLoading(true);
    try {
      const [sources, summary] = await Promise.all([
        fetchDataSources(),
        fetchDashboardSummary(),
      ]);
      setData({ sources, summary });
      if (showToast) toast.success("來源總覽已更新");
    } catch (error) {
      toast.error("讀取來源總覽失敗", {
        description: error instanceof Error ? error.message : String(error),
      });
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    let active = true;
    Promise.all([
      fetchDataSources(),
      fetchDashboardSummary(),
    ])
      .then(([sources, summary]) => {
        if (active) setData({ sources, summary });
      })
      .catch((error) => {
        if (!active) return;
        toast.error("讀取來源總覽失敗", {
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

  const source = useMemo(
    () => data?.sources.sources.find((item) => item.key === sourceKey) || null,
    [data, sourceKey]
  );
  const sourceAlerts = useMemo(() => {
    if (!data || !source) return [];
    return data.summary.alerts.filter((alert) => normalizedSourceKey(alert.siem_source) === source.key);
  }, [data, source]);

  async function handleTest() {
    if (!source?.test_supported) return;
    setTesting(true);
    try {
      const result = await testDataSource(source.key);
      if (result.ok) {
        toast.success(result.message_zh);
      } else {
        toast.warning(result.message_zh, {
          description: result.next_step_zh,
        });
      }
    } catch (error) {
      toast.error("來源檢查失敗", {
        description: error instanceof Error ? error.message : String(error),
      });
    } finally {
      setTesting(false);
    }
  }

  if (!loading && !source) {
    return (
      <div className="flex h-full flex-col">
        <PageHeader
          icon={Database}
          title="找不到事件來源"
          description={`目前沒有 ${sourceKey || "這個"} 來源設定。`}
          actions={
            <Button type="button" variant="outline" size="sm" onClick={() => router.push("/settings/sources")}>
              <ArrowLeft data-icon="inline-start" />
              回來源總覽
            </Button>
          }
        />
      </div>
    );
  }

  const view = source ? sourceStatusView(source.status) : sourceStatusView("disabled");
  const settingsHref = source ? sourceSettingsHref(source) : "";
  const { sourceCapabilities, responseCapabilities } = source
    ? splitCapabilities(source)
    : { sourceCapabilities: [], responseCapabilities: [] };
  const lastEvent = sourceAlerts
    .map((alert) => alert.timestamp)
    .sort()
    .at(-1);

  return (
    <div className="flex h-full flex-col">
      <PageHeader
        icon={Database}
        title={source ? `${source.label_zh} 來源總覽` : "來源總覽"}
        description="先看這個來源現在是否能收事件、能查證、能安全處置，再進入細節設定。"
        actions={
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={() => void loadData(true)}
            disabled={loading}
          >
            <RefreshCw data-icon="inline-start" className={loading ? "animate-spin" : ""} />
            重新整理
          </Button>
        }
      />

      <main className="flex-1 overflow-auto p-6">
        <div className="mx-auto max-w-6xl space-y-6">
          {source && (
            <>
              <Card className={cn("border", view.tone)}>
                <CardContent className="grid gap-5 p-5 lg:grid-cols-[1fr_auto] lg:items-start">
                  <div className="min-w-0 space-y-3">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className={cn("size-2.5 rounded-full", view.dot)} />
                      <h2 className="text-xl font-semibold">{source.label_zh}</h2>
                      {source.primary && <Badge variant="secondary">先鋒來源</Badge>}
                      <Badge className={view.badge} variant={view.badge ? "secondary" : "outline"}>
                        {view.label}
                      </Badge>
                    </div>
                    <p className="text-sm text-muted-foreground">
                      {source.category_zh} · {source.product_zh}
                    </p>
                    <p className="max-w-3xl text-sm leading-6">{source.summary_zh}</p>
                    <div className="flex flex-wrap gap-2">
                      {(source.agent_roles || []).map((role) => (
                        <SourceRolePill
                          key={role}
                          label={
                            role === "security_source"
                              ? "事件來源"
                              : role === "evidence_provider"
                                ? "查證能力"
                                : role === "response_provider"
                                  ? "處置能力"
                                  : role
                          }
                        />
                      ))}
                    </div>
                  </div>
                  <SourceActions source={source} testing={testing} onTest={() => void handleTest()} />
                </CardContent>
              </Card>

              <div className="grid gap-3 md:grid-cols-4">
                <SourceMetric label="目前載入事件" value={sourceAlerts.length} detail="依 Dashboard 目前資料計算" />
                <SourceMetric label="最後事件" value={formatLastEvent(lastEvent)} detail="沒有事件時顯示 -" />
                <SourceMetric
                  label="查證能力"
                  value={`${readyCount(sourceCapabilities)}/${sourceCapabilities.length}`}
                  detail="ready / total"
                />
                <SourceMetric
                  label="處置能力"
                  value={`${readyCount(responseCapabilities)}/${responseCapabilities.length}`}
                  detail="ready / total"
                />
              </div>

              {source.key === "wazuh" && (
                <WazuhConnectionGuide settingsHref={settingsHref} />
              )}

              <div className="grid gap-4 lg:grid-cols-2">
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2 text-base">
                      <BarChart3 className="size-4" />
                      來源與查證能力
                    </CardTitle>
                    <CardDescription>事件入口與查證能力是否已可使用。</CardDescription>
                  </CardHeader>
                  <CardContent className="flex flex-wrap gap-2">
                    {sourceCapabilities.map((capability) => (
                      <CapabilityPill key={capability.key} capability={capability} />
                    ))}
                    {!sourceCapabilities.length && (
                      <span className="text-sm text-muted-foreground">尚未開放事件或查證能力。</span>
                    )}
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2 text-base">
                      <CheckCircle2 className="size-4" />
                      受控處置能力
                    </CardTitle>
                    <CardDescription>只有人工確認後才會執行破壞性動作。</CardDescription>
                  </CardHeader>
                  <CardContent className="flex flex-wrap gap-2">
                    {responseCapabilities.map((capability) => (
                      <CapabilityPill key={capability.key} capability={capability} />
                    ))}
                    {!responseCapabilities.length && (
                      <span className="text-sm text-muted-foreground">尚未開放處置動作。</span>
                    )}
                  </CardContent>
                </Card>
              </div>

              <FollowUpCard source={source} />
            </>
          )}
        </div>
      </main>
    </div>
  );
}

"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import {
  Database,
  ExternalLink,
  PlugZap,
  RefreshCw,
  Settings2,
  ArrowRight,
} from "lucide-react";
import { toast } from "sonner";
import { PageHeader } from "@/components/dashboard/page-header";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardTitle,
} from "@/components/ui/card";
import { fetchDataSources, testDataSource } from "@/lib/api";
import type {
  DataSourceCapability,
  DataSourceItem,
  DataSourcesResponse,
} from "@/lib/types";
import {
  capabilityClass,
  sourceHref,
  sourceSettingsHref,
  sourceRoleLabels,
  sourceStatusView,
  splitCapabilities,
} from "@/lib/source-ui";
import { cn } from "@/lib/utils";

function CapabilityPill({ capability }: { capability: DataSourceCapability }) {
  return (
    <span
      className={cn(
        "rounded-md border px-2 py-1 text-xs font-medium",
        capabilityClass(capability)
      )}
    >
      {capability.label_zh}
    </span>
  );
}

function SourceOverviewRow({
  source,
  testing,
  onConfigure,
  onOpen,
  onTest,
}: {
  source: DataSourceItem;
  testing: boolean;
  onConfigure: (source: DataSourceItem) => void;
  onOpen: (source: DataSourceItem) => void;
  onTest: (source: DataSourceItem) => void;
}) {
  const view = sourceStatusView(source.status);
  const { sourceCapabilities, responseCapabilities } = splitCapabilities(source);

  return (
    <Card className={cn("border", view.tone)}>
      <CardContent className="grid gap-4 p-4 lg:grid-cols-[minmax(0,1.4fr)_minmax(260px,1fr)_auto] lg:items-center">
        <div className="min-w-0 space-y-2">
          <div className="flex flex-wrap items-center gap-2">
            <span className={cn("size-2.5 rounded-full", view.dot)} />
            <CardTitle className="text-base">{source.label_zh}</CardTitle>
            {source.primary && <Badge variant="secondary">先鋒來源</Badge>}
            <Badge className={view.badge} variant={view.badge ? "secondary" : "outline"}>
              {view.label}
            </Badge>
          </div>
          <CardDescription>{source.category_zh} · {source.product_zh}</CardDescription>
          <p className="line-clamp-2 text-sm text-muted-foreground">{source.summary_zh}</p>
        </div>

        <div className="space-y-2">
          <div className="flex flex-wrap gap-2">
            {(source.agent_roles || []).map((role) => (
              <Badge key={role} variant="outline">
                {sourceRoleLabels[role] || role}
              </Badge>
            ))}
          </div>
          <div className="flex flex-wrap gap-2">
            {[...sourceCapabilities, ...responseCapabilities].slice(0, 4).map((capability) => (
              <CapabilityPill key={capability.key} capability={capability} />
            ))}
            {source.capabilities.length > 4 && (
              <span className="rounded-md border bg-background px-2 py-1 text-xs text-muted-foreground">
                +{source.capabilities.length - 4}
              </span>
            )}
          </div>
        </div>

        <div className="flex flex-wrap justify-start gap-2 lg:justify-end">
          <Button type="button" size="sm" onClick={() => onOpen(source)}>
            查看總覽
            <ArrowRight data-icon="inline-end" />
          </Button>
          {source.can_configure && source.settings_href && (
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => onConfigure(source)}
            >
              <Settings2 data-icon="inline-start" />
              設定
            </Button>
          )}
          <Button
            type="button"
            variant={source.test_supported ? "outline" : "secondary"}
            size="sm"
            onClick={() => onTest(source)}
            disabled={!source.test_supported || testing}
          >
            <PlugZap data-icon="inline-start" className={testing ? "animate-pulse" : ""} />
            {source.test_supported ? "檢查" : "尚未開放"}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

export default function DataSourcesPage() {
  const router = useRouter();
  const [data, setData] = useState<DataSourcesResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [testingSource, setTestingSource] = useState("");

  const loadSources = useCallback(async (showToast = false) => {
    setLoading(true);
    try {
      const next = await fetchDataSources();
      setData(next);
      if (showToast) toast.success("事件來源狀態已重新載入");
    } catch (error) {
      toast.error("讀取事件來源失敗", {
        description: error instanceof Error ? error.message : String(error),
      });
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    let active = true;
    fetchDataSources()
      .then((next) => {
        if (active) setData(next);
      })
      .catch((error) => {
        if (!active) return;
        toast.error("讀取事件來源失敗", {
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

  const sourceCounts = useMemo(() => {
    const sources = data?.sources || [];
    return {
      active: sources.filter((source) => source.status === "active").length,
      planned: sources.filter((source) => source.status === "planned").length,
      responseProviders: data?.response_providers_ready
        ?? sources.filter((source) => (
          source.status === "active" && (source.agent_roles || []).includes("response_provider")
        )).length,
    };
  }, [data]);
  const activeSources = useMemo(
    () => (data?.sources || []).filter((source) => source.status !== "planned"),
    [data]
  );
  const plannedSources = useMemo(
    () => (data?.sources || []).filter((source) => source.status === "planned"),
    [data]
  );

  async function handleTest(source: DataSourceItem) {
    if (!source.test_supported) return;
    setTestingSource(source.key);
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
      setTestingSource("");
    }
  }

  return (
    <div className="flex h-full flex-col">
      <PageHeader
        icon={Database}
        title="事件來源"
        description="這是 EdgeSec-Pi 接收資安訊號的入口總覽：Wazuh 只是第一個先鋒來源，未來 Google Workspace、Microsoft 365、Firewall 或 EDR 都會以同一套 Agent 建議流程進來。"
        actions={
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={() => void loadSources(true)}
            disabled={loading}
          >
            <RefreshCw data-icon="inline-start" className={loading ? "animate-spin" : ""} />
            重新載入
          </Button>
        }
      />

      <main className="flex-1 overflow-auto p-6">
        <div className="mb-4 grid gap-3 md:grid-cols-4">
          <div className="rounded-lg border bg-card p-4">
            <div className="text-xs font-medium text-muted-foreground">已接事件來源</div>
            <div className="mt-2 text-2xl font-semibold">{sourceCounts.active}</div>
          </div>
          <div className="rounded-lg border bg-card p-4">
            <div className="text-xs font-medium text-muted-foreground">具處置能力</div>
            <div className="mt-2 text-2xl font-semibold">{sourceCounts.responseProviders}</div>
          </div>
          <div className="rounded-lg border bg-card p-4">
            <div className="text-xs font-medium text-muted-foreground">預留來源</div>
            <div className="mt-2 text-2xl font-semibold">{sourceCounts.planned}</div>
          </div>
          <div className="rounded-lg border bg-card p-4">
            <div className="flex items-center gap-2 text-xs font-medium text-muted-foreground">
              <ExternalLink className="size-3.5" />
              Canonical schema
            </div>
            <div className="mt-2 text-2xl font-semibold">
              v{data?.canonical_schema_version || "-"}
            </div>
          </div>
        </div>

        {data?.message_zh && (
          <div className="mb-4 rounded-lg border bg-muted/40 px-4 py-3 text-sm text-muted-foreground">
            {data.message_zh}
          </div>
        )}

        <div className="mb-4 rounded-lg border bg-card p-4">
          <h2 className="text-base font-semibold">這一頁在做什麼？</h2>
          <p className="mt-2 text-sm leading-6 text-muted-foreground">
            EdgeSec-Pi 的 Dashboard 是 Agent 建議中心，不直接取代 Wazuh、M365 或 EDR。
            這裡先確認哪些系統會把事件送進來、哪些系統可補證據、哪些系統能做受控處置。
            事件進來後會被轉成一致格式，再由 Agent 用白話告訴老闆要不要介入。
          </p>
        </div>

        <section className="space-y-3">
          <div>
            <h2 className="text-lg font-semibold">來源總覽</h2>
            <p className="mt-1 text-sm text-muted-foreground">
              這裡只放每個來源的健康狀態與入口；單一來源的統計、查證與處置設定請進來源頁。
            </p>
          </div>
          <div className="space-y-3">
            {activeSources.map((source) => (
              <SourceOverviewRow
                key={source.key}
                source={source}
                testing={testingSource === source.key}
                onOpen={(item) => router.push(sourceHref(item.key))}
                onConfigure={(item) => router.push(sourceSettingsHref(item))}
                onTest={(item) => void handleTest(item)}
              />
            ))}
          </div>
        </section>

        {plannedSources.length > 0 && (
          <section className="mt-6 space-y-3">
            <div>
              <h2 className="text-lg font-semibold">預留來源</h2>
              <p className="mt-1 text-sm text-muted-foreground">
                這些來源已保留 canonical schema 與 UI 入口，尚未開放設定。
              </p>
            </div>
            <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
              {plannedSources.map((source) => {
                const view = sourceStatusView(source.status);
                return (
                  <button
                    key={source.key}
                    type="button"
                    className="rounded-lg border bg-card p-4 text-left transition hover:border-primary/40 hover:bg-muted/40"
                    onClick={() => router.push(sourceHref(source.key))}
                  >
                    <div className="flex items-center justify-between gap-3">
                      <div className="font-medium">{source.label_zh}</div>
                      <Badge className={view.badge} variant="secondary">
                        {view.label}
                      </Badge>
                    </div>
                    <p className="mt-2 line-clamp-2 text-sm text-muted-foreground">
                      {source.summary_zh}
                    </p>
                  </button>
                );
              })}
            </div>
          </section>
        )}

        {!loading && !data?.sources?.length && (
          <div className="rounded-lg border bg-card p-8 text-center text-sm text-muted-foreground">
            目前沒有資料來源資訊。
          </div>
        )}
      </main>
    </div>
  );
}

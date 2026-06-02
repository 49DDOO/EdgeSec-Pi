"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Bell,
  BrainCircuit,
  CheckCircle2,
  Circle,
  ClipboardCheck,
  Database,
  Monitor,
  RefreshCw,
  Send,
  Server,
  ShieldCheck,
  SlidersHorizontal,
  UserRoundCog,
  type LucideIcon,
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
  fetchAiSettings,
  fetchDashboardSummary,
  fetchDataSources,
  fetchNotificationSettings,
  fetchServiceStatus,
  fetchWazuhSettings,
  replayBuiltInTestAlert,
  type DashboardSummary,
  type NotificationSettingsResponse,
} from "@/lib/api";
import { buildSetupFlow } from "@/lib/setup-flow";
import { sourceSettingsHref } from "@/lib/source-ui";
import type {
  AiSettings,
  DataSourceItem,
  DataSourcesResponse,
  ServiceStatusResponse,
  SetupStepId,
  SetupStepModel,
  SetupStepState,
  WazuhSettings,
} from "@/lib/types";
import { cn } from "@/lib/utils";

interface SetupData {
  summary: DashboardSummary;
  serviceStatus: ServiceStatusResponse;
  notifications: NotificationSettingsResponse;
  ai: AiSettings;
  wazuh: WazuhSettings;
  sources: DataSourcesResponse;
}

const STEP_ICONS: Record<SetupStepId, LucideIcon> = {
  wazuh: Server,
  ai: BrainCircuit,
  notify: Bell,
  agent: Monitor,
  hardening: SlidersHorizontal,
  context: UserRoundCog,
  test: ShieldCheck,
};

function stateView(state: SetupStepState) {
  if (state === "done") {
    return {
      label: "完成",
      icon: CheckCircle2,
      badge: "bg-emerald-600 text-white hover:bg-emerald-600",
      card: "border-emerald-200 bg-emerald-50/35",
      iconClass: "text-emerald-600",
    };
  }
  if (state === "attention") {
    return {
      label: "需確認",
      icon: ClipboardCheck,
      badge: "bg-amber-500 text-white hover:bg-amber-500",
      card: "border-amber-200 bg-amber-50/40",
      iconClass: "text-amber-600",
    };
  }
  return {
    label: "待設定",
    icon: Circle,
    badge: "bg-muted text-muted-foreground hover:bg-muted",
    card: "border-border bg-card",
    iconClass: "text-muted-foreground",
  };
}

function sourceStatusLabel(source: DataSourceItem) {
  if (source.status === "active") return "已接上";
  if (source.status === "needs_setup") return "待設定";
  if (source.status === "planned") return "預留";
  return "未啟用";
}

const LAUNCH_STEP_IDS = new Set<SetupStepId>(["wazuh", "ai", "notify", "test"]);

function nextStepSummary(step: SetupStepModel) {
  if (step.id === "wazuh") return "先確認 Wazuh Alert 能送進來，Manager / Indexer 查得到資料。";
  if (step.id === "ai") return "接著確認模型能把事件翻成老闆看得懂的建議。";
  if (step.id === "notify") return "再測通至少一個通知管道，事件才會主動送到人手上。";
  if (step.id === "test") return "送一筆內建測試事件，確認事件、AI、Dashboard 與通知串起來。";
  if (step.id === "agent") return "核心流程通了之後，再部署或確認真實端點在線。";
  if (step.id === "context") return "補上端點用途、負責人與重要程度，Agent 建議才會更像人話。";
  if (step.id === "hardening") return "最後讓 IT 強化 Wazuh 訊號品質；細節可看下方卡片。";
  return step.detail;
}

function SetupStepCard({
  step,
  index,
  onSendBuiltInTest,
  sendingTest,
}: {
  step: SetupStepModel;
  index: number;
  onSendBuiltInTest: () => void;
  sendingTest: boolean;
}) {
  const view = stateView(step.state);
  const StateIcon = view.icon;
  const StepIcon = STEP_ICONS[step.id];
  return (
    <Card className={cn("border", step.primary && view.card)}>
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between gap-4">
          <div className="flex items-start gap-3">
            <div className="flex size-9 shrink-0 items-center justify-center rounded-lg bg-muted">
              <StepIcon className="size-5" />
            </div>
            <div>
              <CardTitle className="text-base">
                {index + 1}. {step.title}
              </CardTitle>
              <CardDescription className="mt-1">
                {step.description}
              </CardDescription>
            </div>
          </div>
          <Badge className={view.badge}>
            <StateIcon className="mr-1 size-3.5" />
            {view.label}
          </Badge>
        </div>
      </CardHeader>
      <CardContent className="space-y-4 pt-0 text-sm">
        <p className="text-muted-foreground">{step.detail}</p>
        <div className="flex flex-wrap gap-2">
          <Link
            className={buttonVariants({ variant: step.primary ? "default" : "outline" })}
            href={step.href}
          >
            {step.cta}
          </Link>
          {step.id === "test" && (
            <Button
              variant="outline"
              onClick={onSendBuiltInTest}
              disabled={sendingTest}
            >
              <Send data-icon="inline-start" />
              {sendingTest ? "送出中..." : "直接送測試事件"}
            </Button>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

export default function SetupPage() {
  const [data, setData] = useState<SetupData | null>(null);
  const [loading, setLoading] = useState(true);
  const [sendingTest, setSendingTest] = useState(false);
  const [selectedSourceKey, setSelectedSourceKey] = useState("");

  const loadData = useCallback(async (showToast = false) => {
    setLoading(true);
    try {
      const [summary, serviceStatus, notifications, ai, wazuh, sources] = await Promise.all([
        fetchDashboardSummary(),
        fetchServiceStatus(),
        fetchNotificationSettings(),
        fetchAiSettings(),
        fetchWazuhSettings(),
        fetchDataSources(),
      ]);
      setData({ summary, serviceStatus, notifications, ai, wazuh, sources });
      if (showToast) toast.success("首次設定狀態已更新");
    } catch (error) {
      toast.error("讀取首次設定狀態失敗", {
        description: error instanceof Error ? error.message : String(error),
      });
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    let active = true;
    const sourceFromUrl = new URLSearchParams(window.location.search).get("source") || "";
    Promise.all([
      fetchDashboardSummary(),
      fetchServiceStatus(),
      fetchNotificationSettings(),
      fetchAiSettings(),
      fetchWazuhSettings(),
      fetchDataSources(),
    ])
      .then(([summary, serviceStatus, notifications, ai, wazuh, sources]) => {
        if (!active) return;
        setData({ summary, serviceStatus, notifications, ai, wazuh, sources });
        if (sourceFromUrl) {
          setSelectedSourceKey(sourceFromUrl);
          return;
        }
        const setupSources = sources.sources.filter((source) => source.setup_href && source.status !== "planned");
        if (setupSources.length === 1) setSelectedSourceKey(setupSources[0].key);
      })
      .catch((error) => {
        if (!active) return;
        toast.error("讀取首次設定狀態失敗", {
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

  async function sendBuiltInTest() {
    setSendingTest(true);
    try {
      const result = await replayBuiltInTestAlert();
      toast.success("測試事件已送出", {
        description: result.message,
      });
      await loadData(false);
    } catch (error) {
      toast.error("送出測試事件失敗", {
        description: error instanceof Error ? error.message : String(error),
      });
    } finally {
      setSendingTest(false);
    }
  }

  const { steps, doneCount, progress, nextStep } = useMemo(() => buildSetupFlow(data), [data]);
  const setupSources = useMemo(
    () => (data?.sources.sources || []).filter((source) => source.setup_href && source.status !== "planned"),
    [data]
  );
  const plannedSources = useMemo(
    () => (data?.sources.sources || []).filter((source) => source.status === "planned"),
    [data]
  );
  const selectedSource = useMemo(() => {
    if (!data || !selectedSourceKey) return null;
    return data.sources.sources.find((source) => source.key === selectedSourceKey) || null;
  }, [data, selectedSourceKey]);
  const launchSteps = useMemo(() => steps.filter((step) => LAUNCH_STEP_IDS.has(step.id)), [steps]);
  const followUpSteps = useMemo(() => steps.filter((step) => !LAUNCH_STEP_IDS.has(step.id)), [steps]);
  const showSourcePicker = !selectedSourceKey || !selectedSource;

  return (
    <div className="flex h-full flex-col">
      <PageHeader
        icon={ClipboardCheck}
        title="首次設定"
        description="先選會送進事件的上游來源，再完成該來源的查證、處置、AI 與通知設定。"
        actions={
          <Button variant="outline" onClick={() => void loadData(true)} disabled={loading}>
            <RefreshCw data-icon="inline-start" className={cn(loading && "animate-spin")} />
            重新整理
          </Button>
        }
      />

      <main className="flex-1 overflow-auto p-6">
        <div className="mx-auto max-w-6xl space-y-6">
          {loading && !data && (
            <Card>
              <CardContent className="p-6 text-sm text-muted-foreground">
                正在整理首次設定狀態...
              </CardContent>
            </Card>
          )}

          {showSourcePicker && data && (
            <>
              <Card>
                <CardContent className="grid gap-6 p-6 lg:grid-cols-[1fr_320px]">
                  <div>
                    <div className="text-sm font-medium text-muted-foreground">第 1 步</div>
                    <h2 className="mt-2 text-2xl font-semibold">先選事件來源</h2>
                    <p className="mt-3 max-w-2xl text-sm leading-6 text-muted-foreground">
                      首次設定先確認哪個上游系統會把資安事件送進來。現在可設定的是 Wazuh Alert；MCP、Wazuh API 與 Active Response 是它周邊的查證與處置能力。
                    </p>
                  </div>
                  <div className="rounded-lg border bg-muted/30 p-4 text-sm">
                    <div className="font-semibold">流程規則</div>
                    <p className="mt-2 text-muted-foreground">
                      事件來源未確定前，不展開 Agent 建議、MCP 查證、隔離或雲端權限等來源專屬步驟。若只有一個可設定來源，系統會自動帶你進下一步。
                    </p>
                    <Link className={buttonVariants({ variant: "outline", className: "mt-4 w-full" })} href="/settings/sources">
                      查看事件來源
                    </Link>
                  </div>
                </CardContent>
              </Card>

              <div className="grid gap-4 xl:grid-cols-2">
                {setupSources.map((source) => (
                  <Card key={source.key} className={cn("border", source.primary && "border-primary/30 bg-primary/5")}>
                    <CardHeader className="pb-3">
                      <div className="flex items-start justify-between gap-3">
                        <div className="space-y-1">
                          <div className="flex flex-wrap items-center gap-2">
                            <CardTitle className="text-base">{source.label_zh}</CardTitle>
                            {source.primary && <Badge variant="secondary">先鋒來源</Badge>}
                            <Badge variant="outline">{sourceStatusLabel(source)}</Badge>
                          </div>
                          <CardDescription>{source.category_zh} · {source.product_zh}</CardDescription>
                        </div>
                        <Database className="size-5 shrink-0 text-muted-foreground" />
                      </div>
                    </CardHeader>
                    <CardContent className="space-y-4 text-sm">
                      <p className="leading-6 text-muted-foreground">{source.summary_zh}</p>
                      <div className="rounded-lg border bg-background/80 p-3">
                        <div className="font-medium text-foreground">Agent 建議需要的能力</div>
                        <div className="mt-1 leading-6 text-muted-foreground">{source.next_step_zh}</div>
                      </div>
                      <div className="flex flex-wrap gap-2">
                        {source.setup_href ? (
                          <Link
                            className={buttonVariants()}
                            href={source.setup_href}
                            onClick={() => setSelectedSourceKey(source.key)}
                          >
                            {source.status === "active" ? "繼續設定" : "開始設定"}
                          </Link>
                        ) : (
                          <Button type="button" disabled variant="secondary">
                            尚未開放
                          </Button>
                        )}
                        {source.settings_href && (
                          <Link className={buttonVariants({ variant: "outline" })} href={sourceSettingsHref(source)}>
                            詳細設定
                          </Link>
                        )}
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>

              {plannedSources.length > 0 && (
                <Card>
                  <CardHeader>
                    <CardTitle className="text-base">未開放來源</CardTitle>
                    <CardDescription>
                      這些是未來可接入的事件來源，不會影響目前 Wazuh Alert 的首次設定。
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="flex flex-wrap gap-2">
                    {plannedSources.map((source) => (
                      <Badge key={source.key} variant="outline">
                        {source.label_zh}
                      </Badge>
                    ))}
                  </CardContent>
                </Card>
              )}
            </>
          )}

          {!showSourcePicker && selectedSource && (
            <>
          <Card>
            <CardContent className="grid gap-6 p-6 lg:grid-cols-[1fr_300px]">
              <div>
                <div className="text-sm font-medium text-muted-foreground">Agent 建議上線進度</div>
                <div className="mt-1 text-sm text-muted-foreground">
                  已選來源：<span className="font-medium text-foreground">{selectedSource.label_zh}</span>
                </div>
                <div className="mt-2 flex items-end gap-3">
                  <div className="text-4xl font-semibold">{progress}%</div>
                  <div className="pb-1 text-sm text-muted-foreground">{doneCount}/{steps.length} 步完成</div>
                </div>
                <div className="mt-4 h-2 overflow-hidden rounded-full bg-muted">
                  <div className="h-full rounded-full bg-primary transition-all" style={{ width: `${progress}%` }} />
                </div>
                <p className="mt-4 text-sm text-muted-foreground">
                  下一步：<span className="font-medium text-foreground">{nextStep.title}</span>。{nextStepSummary(nextStep)}
                </p>
              </div>
              <div className="rounded-lg border bg-muted/30 p-4 text-sm">
                <div className="font-semibold">下一步操作</div>
                <p className="mt-2 text-muted-foreground">
                  先讓 {selectedSource.label_zh}、AI、通知與測試事件跑通，再補端點背景與訊號強化。
                </p>
                <Link className={buttonVariants({ className: "mt-4 w-full" })} href={nextStep.href}>
                  {nextStep.cta}
                </Link>
                <Link
                  className={buttonVariants({ variant: "outline", className: "mt-2 w-full" })}
                  href="/settings/setup"
                  onClick={() => setSelectedSourceKey("")}
                >
                  重新選擇來源
                </Link>
              </div>
            </CardContent>
          </Card>

          <section className="space-y-3">
            <div>
              <h2 className="text-lg font-semibold">1. 先讓 Agent 建議跑起來</h2>
              <p className="mt-1 text-sm text-muted-foreground">
                先確認事件進得來、AI 會解釋、通知送得到人，最後用測試事件驗證整條線。
              </p>
            </div>
            <div className="grid gap-4 md:grid-cols-2">
              {launchSteps.map((step, index) => (
                <SetupStepCard
                  key={step.id}
                  step={step}
                  index={index}
                  onSendBuiltInTest={() => void sendBuiltInTest()}
                  sendingTest={sendingTest}
                />
              ))}
            </div>
          </section>

          <section className="space-y-3">
            <div>
              <h2 className="text-lg font-semibold">2. 接真實端點與提升訊號品質</h2>
              <p className="mt-1 text-sm text-muted-foreground">
                核心建議流程通了之後，再把真實端點、業務背景與 Wazuh 強化訊號補齊。
              </p>
            </div>
            <div className="grid gap-4 md:grid-cols-2">
              {followUpSteps.map((step, index) => (
                <SetupStepCard
                  key={step.id}
                  step={step}
                  index={launchSteps.length + index}
                  onSendBuiltInTest={() => void sendBuiltInTest()}
                  sendingTest={sendingTest}
                />
              ))}
            </div>
          </section>
            </>
          )}
        </div>
      </main>
    </div>
  );
}

import type {
  AiSettings,
  DataSourcesResponse,
  ServiceCheck,
  ServiceStatusResponse,
  SetupStepModel,
  WazuhSettings,
} from "@/lib/types";
import type {
  DashboardSummary,
  NotificationSettingsResponse,
} from "@/lib/api";

export interface SetupFlowData {
  summary: DashboardSummary;
  serviceStatus: ServiceStatusResponse;
  notifications: NotificationSettingsResponse;
  ai: AiSettings;
  wazuh: WazuhSettings;
  sources: DataSourcesResponse;
}

export interface SetupFlowModel {
  steps: SetupStepModel[];
  doneCount: number;
  progress: number;
  nextStep: SetupStepModel;
}

function serviceById(status: ServiceStatusResponse | null, id: string): ServiceCheck | undefined {
  return status?.services.find((service) => service.id === id);
}

function hardeningDetail(hardeningCheck?: ServiceCheck, moduleFlowCheck?: ServiceCheck): string {
  if (!hardeningCheck?.summary_zh) {
    return "等第一個資料來源與第一台端點上線後，再確認 agent-groups 強化包。";
  }
  const groupText = `${hardeningCheck.summary_zh}${hardeningCheck.next_step_zh ? ` ${hardeningCheck.next_step_zh}` : ""}`;
  const flowText = moduleFlowCheck?.summary_zh
    ? `事件流佐證：${moduleFlowCheck.summary_zh}${moduleFlowCheck.next_step_zh ? ` ${moduleFlowCheck.next_step_zh}` : ""}`
    : "事件流佐證：尚未讀取最近事件。";
  return `${groupText} ${flowText} 已套用群組不代表每個偵測模組都有事件流。`;
}

function missingCoreSetup(wazuhDone: boolean, aiDone: boolean, testedChannels: number): string {
  const missing: string[] = [];
  if (!wazuhDone) missing.push("Wazuh Alert 來源");
  if (!aiDone) missing.push("AI 判讀");
  if (testedChannels === 0) missing.push("通知測試");
  return missing.length
    ? `請先完成 ${missing.join("、")}，再送端到端測試事件。`
    : "送出一筆內建測試事件，確認 Dashboard 與通知都看得到。";
}

export function buildSetupSteps(data: SetupFlowData | null): SetupStepModel[] {
  if (!data) {
    return [
      { id: "wazuh", title: "接上 Wazuh Alert", description: "確認上游事件來源、Manager 與 Indexer。", state: "todo", scope: "source", detail: "正在讀取狀態。", href: "/settings/sources/wazuh/settings", cta: "設定 Wazuh", primary: true },
      { id: "ai", title: "設定 AI", description: "確認模型可以把事件翻成白話。", state: "todo", scope: "global", detail: "正在讀取狀態。", href: "/settings/ai-model", cta: "設定 AI" },
      { id: "notify", title: "設定通知", description: "至少測通一個通知管道。", state: "todo", scope: "global", detail: "正在讀取狀態。", href: "/settings/notifications", cta: "設定通知" },
      { id: "test", title: "送測試事件", description: "跑一次完整鏈路。", state: "todo", scope: "global", detail: "正在讀取狀態。", href: "/settings/testing", cta: "前往測試" },
      { id: "agent", title: "部署第一台端點", description: "讓 Wazuh Agent 回報真實端點狀態。", state: "todo", scope: "source", detail: "正在讀取狀態。", href: "/settings/endpoints?section=install", cta: "部署端點" },
      { id: "context", title: "補業務背景", description: "讓事件能說清楚影響誰與哪個流程。", state: "todo", scope: "source", detail: "正在讀取狀態。", href: "/settings/endpoints?section=inventory", cta: "補背景" },
      { id: "hardening", title: "啟用訊號強化", description: "確認 Wazuh Agent 已套用 agent-groups 並有事件流。", state: "todo", scope: "source", detail: "正在讀取狀態。", href: "/settings/sources/wazuh/detections", cta: "查看訊號" },
    ];
  }

  const selectedSource = data.sources.sources.find((source) => source.key === "wazuh");
  const wazuhApi = serviceById(data.serviceStatus, "wazuh_api");
  const hardeningCheck = serviceById(data.serviceStatus, "wazuh_hardening");
  const moduleFlowCheck = serviceById(data.serviceStatus, "wazuh_module_flow");
  const aiCheck = serviceById(data.serviceStatus, "lm_studio");
  const alertFlow = serviceById(data.serviceStatus, "alert_flow");
  const testedChannels = Object.values(data.notifications.channels).filter((channel) => channel.lastTested);
  const configuredChannels = Object.values(data.notifications.channels).filter((channel) => channel.configured);
  const onlineEndpoints = data.summary.endpoints.filter((endpoint) => endpoint.status === "online");
  const profiledEndpoints = data.summary.endpoints.filter((endpoint) => endpoint.business_context?.configured);
  const wazuhConfigured = data.wazuh.WAZUH_API_PASS_configured && data.wazuh.WAZUH_INDEXER_PASS_configured;
  const wazuhMode = data.wazuh.WAZUH_DEPLOYMENT_MODE || "existing";
  const wazuhModeLabel = data.wazuh.WAZUH_DEPLOYMENT_LABEL_ZH || selectedSource?.deployment_label_zh || "連接現有 Wazuh";
  const wazuhDone = wazuhConfigured && wazuhApi?.status === "ok";
  const aiDone = data.ai.enabled && aiCheck?.status === "ok";
  const hardeningDone = hardeningCheck?.status === "ok" && moduleFlowCheck?.status === "ok";
  const coreTestReady = wazuhDone && aiDone && testedChannels.length > 0;

  return [
    {
      id: "wazuh",
      title: "接上 Wazuh Alert",
      description: "先決定使用 EdgeSec 代管、連接現有環境，或本機快速體驗。",
      state: wazuhMode === "managed" && !wazuhConfigured ? "attention" : wazuhDone ? "done" : wazuhConfigured ? "attention" : "todo",
      scope: "source",
      detail: wazuhMode === "managed" && !wazuhConfigured
        ? "已選 EdgeSec 代管 Wazuh；目前尚未接雲端開通流程，正式產品會由平台寫入連線憑證。"
        : wazuhDone
          ? `${wazuhModeLabel} 已設定，Wazuh Manager 可連線。`
          : wazuhConfigured
            ? wazuhApi?.summary_zh || `${wazuhModeLabel} 密碼已設定，請測試 Manager 與 Indexer。`
            : selectedSource?.next_step_zh || "請先完成 Manager / Indexer 連線設定。",
      href: "/settings/wazuh",
      cta: wazuhDone ? "查看 Wazuh 設定" : "選擇 Wazuh 使用方式",
      primary: !wazuhDone,
    },
    {
      id: "ai",
      title: "設定 AI",
      description: "確認模型可用，之後新事件會送 AI 解析。",
      state: aiDone ? "done" : data.ai.enabled ? "attention" : "todo",
      scope: "global",
      detail: aiDone
        ? `目前使用 ${data.ai.model}。`
        : aiCheck?.summary_zh || "請設定並測試目前使用的 AI 模型。",
      href: "/settings/ai-model",
      cta: aiDone ? "查看 AI" : "設定 AI",
      primary: wazuhDone && !aiDone,
    },
    {
      id: "notify",
      title: "設定通知",
      description: "至少測通一個通知管道，事件通知才會主動送達。",
      state: testedChannels.length > 0 ? "done" : configuredChannels.length > 0 ? "attention" : "todo",
      scope: "global",
      detail: testedChannels.length > 0
        ? `已測通 ${testedChannels.map((channel) => channel.channel.toUpperCase()).join(", ")}。`
        : configuredChannels.length > 0
          ? "已有通知設定，但還沒有測試成功。"
          : "請先設定 LINE、Slack、Telegram 或 Email 其中一個。",
      href: "/settings/notifications",
      cta: testedChannels.length > 0 ? "查看通知" : "設定通知",
      primary: wazuhDone && aiDone && testedChannels.length === 0,
    },
    {
      id: "test",
      title: "送測試事件",
      description: "確認事件、AI、Dashboard 與通知串得起來。",
      state: alertFlow?.status === "ok" ? "done" : coreTestReady ? "attention" : "todo",
      scope: "global",
      detail: alertFlow?.status === "ok"
        ? alertFlow.summary_zh
        : missingCoreSetup(wazuhDone, aiDone, testedChannels.length),
      href: "/settings/testing",
      cta: alertFlow?.status === "ok" ? "查看測試" : "前往測試",
      primary: coreTestReady && alertFlow?.status !== "ok",
    },
    {
      id: "agent",
      title: "部署 Wazuh Agent",
      description: "至少要有一台端點 online，才算開始監控。",
      state: onlineEndpoints.length > 0 ? "done" : data.summary.endpoints.length > 0 ? "attention" : "todo",
      scope: "source",
      detail: onlineEndpoints.length > 0
        ? `${onlineEndpoints.length} 台端點在線。`
        : data.summary.endpoints.length > 0
          ? "已有端點資料，但目前沒有在線端點。"
          : "核心建議流程測通後，請部署第一台監控 Agent 接真實端點事件。",
      href: "/settings/endpoints?section=install",
      cta: onlineEndpoints.length > 0 ? "查看端點" : "部署端點",
      primary: alertFlow?.status === "ok" && onlineEndpoints.length === 0,
    },
    {
      id: "context",
      title: "補業務背景",
      description: "補用途、負責人與重要程度，事件才會像給老闆看的話。",
      state: profiledEndpoints.length > 0 ? "done" : onlineEndpoints.length > 0 ? "attention" : "todo",
      scope: "source",
      detail: profiledEndpoints.length > 0
        ? `${profiledEndpoints.length} 台端點已有業務背景。`
        : onlineEndpoints.length > 0
          ? "已有在線端點，請補上用途、負責人與重要程度。"
          : "等第一台端點上線後再補背景。",
      href: "/settings/endpoints?section=inventory",
      cta: profiledEndpoints.length > 0 ? "查看背景" : "補業務背景",
      primary: onlineEndpoints.length > 0 && profiledEndpoints.length === 0,
    },
    {
      id: "hardening",
      title: "啟用 Wazuh 訊號強化",
      description: "確認 Wazuh Agent 已套用 agent-groups，並用近期事件流做第二層佐證。",
      state: hardeningDone
        ? "done"
        : onlineEndpoints.length > 0 && wazuhDone
          ? "attention"
          : "todo",
      scope: "source",
      detail: hardeningDetail(hardeningCheck, moduleFlowCheck),
      href: "/settings/sources/wazuh/detections",
      cta: hardeningDone ? "查看訊號" : "查看訊號設定",
      primary: onlineEndpoints.length > 0 && profiledEndpoints.length > 0 && !hardeningDone,
    },
  ];
}

export function buildSetupFlow(data: SetupFlowData | null): SetupFlowModel {
  const steps = buildSetupSteps(data);
  const doneCount = steps.filter((step) => step.state === "done").length;
  const progress = Math.round((doneCount / steps.length) * 100);
  const nextStep = steps.find((step) => step.state !== "done") || steps[steps.length - 1];

  return { steps, doneCount, progress, nextStep };
}

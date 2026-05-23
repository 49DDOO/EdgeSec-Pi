import type {
  Alert,
  AlertStatus,
  AlertTrend,
  Endpoint,
  EndpointBusinessContext,
  NotificationConfig,
  RiskSummary,
  ServiceStatusResponse,
  SystemHealth,
} from "@/lib/types";

export interface DashboardSummary {
  generated_at: string;
  alerts: Alert[];
  riskSummary: RiskSummary;
  endpoints: Endpoint[];
  systemHealth: SystemHealth;
  notifications: NotificationConfig;
  install?: {
    manager_host?: string;
    bridge_public_url?: string;
    wazuh_agent_version?: string;
  };
  alertTrends: AlertTrend[];
  demo?: boolean;
  error?: string;
}

export interface NotificationField {
  label: string;
  value?: string | boolean;
  secret?: boolean;
  configured?: boolean;
}

export interface NotificationChannelStatus {
  channel: "line" | "slack" | "telegram" | "email";
  configured: boolean;
  enabled: boolean;
  lastTested: string | null;
  fields: Record<string, NotificationField>;
}

export interface NotificationSettingsResponse {
  channels: Record<NotificationChannelStatus["channel"], NotificationChannelStatus>;
  message?: string;
}

export interface SampleDataStatus {
  category: string;
  index_pattern: string;
  available: boolean;
  total: number;
  sampledata_total: number;
}

export interface SampleDataReplayResult {
  queued: number;
  queue_size: number;
  sampledata: boolean;
  category: string;
  message: string;
}

const API_BASE = (process.env.NEXT_PUBLIC_BRIDGE_API_BASE || "").replace(/\/$/, "");

function apiUrl(path: string) {
  return `${API_BASE}${path}`;
}

export async function fetchDashboardSummary(): Promise<DashboardSummary> {
  const response = await fetch(apiUrl("/api/dashboard/summary"), {
    cache: "no-store",
  });
  if (!response.ok) {
    throw new Error(`Dashboard API ${response.status}`);
  }
  return (await response.json()) as DashboardSummary;
}

export async function updateAlertStatus(alertId: string, status: AlertStatus): Promise<void> {
  const response = await fetch(apiUrl(`/api/dashboard/alerts/${alertId}/case`), {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ status }),
  });
  if (!response.ok) {
    throw new Error(`Update alert failed: ${response.status}`);
  }
}

async function readError(response: Response): Promise<string> {
  try {
    const body = await response.json();
    return String(body.detail || body.message || `${response.status}`);
  } catch {
    return `${response.status}`;
  }
}

export async function fetchNotificationSettings(): Promise<NotificationSettingsResponse> {
  const response = await fetch(apiUrl("/api/dashboard/notifications"), {
    cache: "no-store",
  });
  if (!response.ok) {
    throw new Error(`讀取通知設定失敗：${await readError(response)}`);
  }
  return (await response.json()) as NotificationSettingsResponse;
}

export async function saveNotificationSettings(
  channel: NotificationChannelStatus["channel"],
  values: Record<string, string | boolean>
): Promise<NotificationSettingsResponse> {
  const response = await fetch(apiUrl(`/api/dashboard/notifications/${channel}`), {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ values }),
  });
  if (!response.ok) {
    throw new Error(await readError(response));
  }
  return (await response.json()) as NotificationSettingsResponse;
}

export async function testNotificationChannel(
  channel: NotificationChannelStatus["channel"]
): Promise<NotificationSettingsResponse> {
  const response = await fetch(apiUrl(`/api/dashboard/notifications/${channel}/test`), {
    method: "POST",
  });
  if (!response.ok) {
    throw new Error(await readError(response));
  }
  return (await response.json()) as NotificationSettingsResponse;
}

export async function fetchSampleDataStatus(category = "security"): Promise<SampleDataStatus> {
  const response = await fetch(apiUrl(`/api/dashboard/sample-data/status?category=${encodeURIComponent(category)}`), {
    cache: "no-store",
  });
  if (!response.ok) {
    throw new Error(`讀取測試資料狀態失敗：${await readError(response)}`);
  }
  return (await response.json()) as SampleDataStatus;
}

export async function replaySampleData(options?: {
  category?: string;
  limit?: number;
  min_level?: number;
}): Promise<SampleDataReplayResult> {
  const response = await fetch(apiUrl("/api/dashboard/sample-data/replay"), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      category: options?.category || "security",
      limit: options?.limit ?? 3,
      min_level: options?.min_level ?? 7,
    }),
  });
  if (!response.ok) {
    throw new Error(`送出測試告警失敗：${await readError(response)}`);
  }
  return (await response.json()) as SampleDataReplayResult;
}

export async function replayBuiltInTestAlert(): Promise<SampleDataReplayResult> {
  const response = await fetch(apiUrl("/api/dashboard/test-alert/replay"), {
    method: "POST",
  });
  if (!response.ok) {
    throw new Error(`送出內建測試告警失敗：${await readError(response)}`);
  }
  return (await response.json()) as SampleDataReplayResult;
}

export async function fetchServiceStatus(): Promise<ServiceStatusResponse> {
  const response = await fetch(apiUrl("/api/dashboard/service-status"), {
    cache: "no-store",
  });
  if (!response.ok) {
    throw new Error(`讀取系統狀態失敗：${await readError(response)}`);
  }
  return (await response.json()) as ServiceStatusResponse;
}

export async function updateEndpointBusinessContext(
  agentName: string,
  context: Omit<EndpointBusinessContext, "configured">
): Promise<void> {
  const response = await fetch(
    apiUrl(`/api/dashboard/endpoints/${encodeURIComponent(agentName)}/business-context`),
    {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(context),
    }
  );
  if (!response.ok) {
    throw new Error(await readError(response));
  }
}

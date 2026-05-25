export type SeverityLevel = "critical" | "high" | "medium" | "low";
export type AlertStatus = "pending" | "acknowledged" | "resolved" | "false_positive";
export type EndpointStatus = "online" | "offline" | "warning";

export interface Alert {
  id: string;
  timestamp: string;
  rule_id: string;
  rule_level?: number;
  rule_description: string;
  siem_source?: string;
  agent_id?: string;
  severity: SeverityLevel;
  agent_name: string;
  agent_ip: string;
  source_ip?: string;
  summary: string;
  business_impact: string;
  recommended_action: string;
  status: AlertStatus;
  purpose?: string;
  mitre?: string;
  iocs?: string[];
  root_cause?: string;
  technical_action?: string;
  full_log?: string;
  sampledata?: boolean;
  technical_evidence?: TechnicalEvidence;
}

export interface TechnicalEvidence {
  source: string;
  module: "authentication" | "sca" | "fim" | "vulnerability" | "rootcheck" | "syscollector" | "windows" | "other" | string;
  rule: {
    id: string;
    level: number;
    description: string;
    groups: string[];
    mitre: string[];
  };
  endpoint: {
    agent_id: string;
    name: string;
    ip: string;
    os?: string;
    version?: string;
    last_seen?: string;
  };
  indicators: {
    source_ip?: string;
    destination_ip?: string;
    username?: string;
    file_path?: string;
    process?: string;
    port?: string;
    hashes?: string[];
    domain?: string;
    cve?: string;
    package?: string;
    package_version?: string;
    iocs?: string[];
  };
  module_context?: Record<string, string>;
  remediation: {
    wazuh?: string;
    llm?: string;
  };
  raw: {
    full_log?: string;
  };
}

export interface Endpoint {
  id: string;
  name: string;
  ip: string;
  raw_ip?: string;
  ip_is_loopback?: boolean;
  os: string;
  version: string;
  status: EndpointStatus;
  last_sync: string;
  purpose: string;
  connection_score?: number;
  health_score?: number | null;
  sca_score?: number | null;
  sca?: EndpointScaSummary;
  business_context?: EndpointBusinessContext;
}

export interface EndpointScaSummary {
  score?: number | null;
  policy?: string;
  policy_id?: string;
  passed?: number;
  failed?: number;
  invalid?: number;
  total?: number;
  last_scan?: string;
  failed_checks?: EndpointScaCheck[];
  plain_failed_checks?: EndpointScaPlainCheck[];
  available?: boolean;
}

export interface EndpointScaCheck {
  id?: string;
  title?: string;
  rationale?: string;
  description?: string;
  remediation?: string;
}

export interface EndpointScaPlainCheck {
  title_zh: string;
  action_zh: string;
  source_title: string;
  source_rationale?: string;
  source_description?: string;
  source_remediation?: string;
  source: "llm_from_wazuh_sca" | "wazuh_raw_fallback" | string;
}

export interface EndpointBusinessContext {
  role: string;
  owner: string;
  criticality: string;
  business_hours: string;
  pci_scope: boolean;
  notes: string;
  configured: boolean;
}

export interface RiskSummary {
  level: SeverityLevel | "normal";
  score: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  total_alerts_today: number;
  pending_actions: number;
}

export interface SystemHealth {
  notification_service: "healthy" | "degraded" | "down";
  analysis_queue: number;
  cve_database_updated: string;
  wazuh_connection: "connected" | "disconnected";
  llm_service: "healthy" | "degraded" | "down";
}

export type AiProviderKey = "lm_studio" | "ollama" | "openai" | "openai_compatible";

export interface AiProviderOption {
  key: AiProviderKey;
  label_zh: string;
  default_base_url: string;
  default_model: string;
  help_zh: string;
  base_url: string;
  chat_completions_url: string;
  model: string;
  timeout_s: number;
  max_concurrent_requests: number;
  api_key_configured: boolean;
  api_key_preview: string;
  is_active: boolean;
}

export interface AiSettings {
  enabled: boolean;
  provider: AiProviderKey;
  active_provider: AiProviderKey;
  base_url: string;
  chat_completions_url: string;
  model: string;
  timeout_s: number;
  max_concurrent_requests: number;
  api_key_configured: boolean;
  api_key_preview: string;
  providers: AiProviderOption[];
  message?: string;
}

export interface AiSettingsTestResult {
  ok: boolean;
  provider: AiProviderKey | string;
  model: string;
  base_url: string;
  reply_preview: string;
  message?: string;
}

export interface AiModelListResult {
  models: string[];
  message?: string;
}

export type ServiceCheckStatus = "ok" | "warn" | "fail" | "skip";

export interface ServiceCheck {
  id: string;
  label_zh: string;
  status: ServiceCheckStatus;
  summary_zh: string;
  next_step_zh?: string;
  detail_zh?: string;
  owner_zh?: string;
  required?: boolean;
}

export interface ServiceStatusResponse {
  overall: "ok" | "warn" | "fail";
  title_zh: string;
  message_zh: string;
  next_step_zh: string;
  checked_at: string;
  refresh_interval_s: number;
  services: ServiceCheck[];
  metrics: {
    queue_size: number;
    queue_max: number;
    workers: number;
    notifications_configured: number;
    notifications_tested: number;
  };
}

export interface NotificationConfig {
  line: boolean;
  slack: boolean;
  telegram: boolean;
  email: boolean;
}

export interface AlertTrend {
  date: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  endpoints?: Record<string, number>;
}

export interface InvestigationMessage {
  role: "user" | "assistant";
  content: string;
}

export interface InvestigationEvidence {
  tool: string;
  args: Record<string, unknown>;
  result_preview?: string;
}

export interface InvestigationChatResponse {
  answer_zh: string;
  evidence: InvestigationEvidence[];
}

export type DetectionCategoryKey =
  | "authentication"
  | "sca"
  | "vulnerability"
  | "fim"
  | "network"
  | "process"
  | "malware"
  | "system"
  | "compliance"
  | "other";

export interface DetectionCategory {
  key: DetectionCategoryKey;
  label_zh: string;
  description_zh: string;
}

export interface DetectionCategorySettings {
  categories: DetectionCategory[];
  enabled: Record<DetectionCategoryKey, boolean>;
  message?: string;
}

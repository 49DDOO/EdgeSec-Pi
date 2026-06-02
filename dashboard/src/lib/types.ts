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
  /** MDR 調查路徑產出的白話說明：AI 做了什麼查證、發現什麼、為何下此判斷（無調查時為空字串） */
  investigation_summary_zh?: string;
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
    hash_before?: Record<string, string>;
    hash_after?: Record<string, string>;
    domain?: string;
    cve?: string;
    package?: string;
    package_version?: string;
    iocs?: string[];
  };
  module_context?: Record<string, string>;
  fim_brief?: {
    title_zh: string;
    category: string;
    severity: string;
    risk_label_zh: string;
    file_path: string;
    event: string;
    event_zh: string;
    changed_by: string;
    process: string;
    changed_at?: string;
    business_meaning_zh: string;
    impact_zh: string;
    recommended_steps_zh: string[];
    it_checks: string[];
    hash_before?: Record<string, string>;
    hash_after?: Record<string, string>;
  };
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

export interface WazuhSettings {
  WAZUH_DEPLOYMENT_MODE: "managed" | "existing" | "local_lab";
  WAZUH_DEPLOYMENT_LABEL_ZH: string;
  WAZUH_API_URL: string;
  WAZUH_API_USER: string;
  WAZUH_API_PASS: string;
  WAZUH_API_PASS_configured: boolean;
  WAZUH_API_PASS_preview: string;
  WAZUH_VERIFY_SSL: boolean;
  WAZUH_INDEXER_URL: string;
  WAZUH_INDEXER_USER: string;
  WAZUH_INDEXER_PASS: string;
  WAZUH_INDEXER_PASS_configured: boolean;
  WAZUH_INDEXER_PASS_preview: string;
  WAZUH_INDEXER_VERIFY_SSL: boolean;
  BRIDGE_PUBLIC_URL: string;
  WEBHOOK_SECRET: string;
  WEBHOOK_SECRET_configured: boolean;
  WEBHOOK_SECRET_preview: string;
  webhook_url: string;
  message?: string;
}

export interface WazuhConnectionTestResult {
  ok: boolean;
  message: string;
  agents_total?: number;
  status?: string;
  cluster_name?: string;
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
  result_log?: string;
}

export interface InvestigationSuggestion {
  label_zh: string;
  description_zh: string;
  action: "handoff_it" | "mark_resolved" | "mark_false_positive" | "mark_normal" | "ask_followup";
  followup_question?: string;
}

export interface InvestigationChatResponse {
  answer_zh: string;
  evidence: InvestigationEvidence[];
  suggestions?: InvestigationSuggestion[];
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
  detail_zh?: string;
}

export type DetectionPresetKey = "conservative" | "recommended" | "expanded" | "custom";

export interface DetectionPreset {
  key: Exclude<DetectionPresetKey, "custom">;
  label_zh: string;
  description_zh: string;
  noise_level: "low" | "medium" | "high";
  enabled: Record<DetectionCategoryKey, boolean>;
}

export interface DetectionNoiseProfile {
  noisy_categories: DetectionCategoryKey[];
  core_disabled: DetectionCategoryKey[];
  false_positive_suppression: boolean;
  warnings: string[];
}

export interface DetectionCategorySettings {
  categories: DetectionCategory[];
  enabled: Record<DetectionCategoryKey, boolean>;
  presets?: DetectionPreset[];
  active_preset?: DetectionPresetKey;
  noise?: DetectionNoiseProfile;
  message?: string;
}

export type DataSourceStatus = "active" | "needs_setup" | "planned" | "disabled" | "error";
export type DataSourceCapabilityState = "ready" | "planned" | "not_available";

export interface DataSourceCapability {
  key: string;
  label_zh: string;
  state: DataSourceCapabilityState;
}

export interface DataSourceItem {
  key: string;
  label_zh: string;
  product_zh: string;
  category_zh: string;
  agent_roles?: Array<"security_source" | "evidence_provider" | "response_provider" | string>;
  deployment_mode?: "managed" | "existing" | "local_lab" | string;
  deployment_label_zh?: string;
  status: DataSourceStatus;
  enabled: boolean;
  configured: boolean;
  primary: boolean;
  can_configure: boolean;
  settings_href: string;
  setup_href: string;
  test_supported: boolean;
  summary_zh: string;
  next_step_zh: string;
  evidence_zh: string[];
  capabilities: DataSourceCapability[];
}

export interface DataSourcesResponse {
  generated_at: string;
  canonical_schema_version: string;
  primary_source: string;
  response_providers_ready?: number;
  sources: DataSourceItem[];
  message_zh: string;
}

export interface DataSourceTestResult {
  ok: boolean;
  source: string;
  status: string;
  message_zh: string;
  next_step_zh?: string;
}

export type SetupStepId = "wazuh" | "ai" | "notify" | "agent" | "hardening" | "context" | "test";
export type SetupStepState = "done" | "attention" | "todo";
export type SetupStepScope = "source" | "global";

export interface SetupStepModel {
  id: SetupStepId;
  title: string;
  description: string;
  state: SetupStepState;
  scope?: SetupStepScope;
  detail: string;
  href: string;
  cta: string;
  primary?: boolean;
}

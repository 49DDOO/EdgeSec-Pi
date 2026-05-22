export type SeverityLevel = "critical" | "high" | "medium" | "low";
export type AlertStatus = "pending" | "acknowledged" | "resolved" | "false_positive";
export type EndpointStatus = "online" | "offline" | "warning";

export interface Alert {
  id: string;
  timestamp: string;
  rule_id: string;
  rule_description: string;
  severity: SeverityLevel;
  agent_name: string;
  agent_ip: string;
  summary: string;
  business_impact: string;
  recommended_action: string;
  status: AlertStatus;
  purpose?: string;
}

export interface Endpoint {
  id: string;
  name: string;
  ip: string;
  os: string;
  version: string;
  status: EndpointStatus;
  last_sync: string;
  purpose: string;
  health_score: number;
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
}

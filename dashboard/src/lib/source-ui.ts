import type {
  DataSourceCapability,
  DataSourceItem,
  DataSourceStatus,
} from "@/lib/types";

export const sourceRoleLabels: Record<string, string> = {
  security_source: "事件來源",
  evidence_provider: "查證能力",
  response_provider: "處置能力",
};

export const responseCapabilityKeys = new Set([
  "active_response",
  "block_ip",
  "isolate_asset",
  "disable_identity",
  "revoke_sessions",
  "create_ticket",
]);

export function sourceHref(sourceKey: string) {
  return `/settings/sources/${encodeURIComponent(sourceKey)}`;
}

export function sourceSettingsHref(source: { key: string; settings_href?: string }) {
  if (source.key === "wazuh") return "/settings/sources/wazuh/settings";
  return source.settings_href || "";
}

export function sourceStatusView(status: DataSourceStatus) {
  if (status === "active") {
    return {
      label: "啟用中",
      badge: "bg-emerald-100 text-emerald-700 hover:bg-emerald-100",
      tone: "border-emerald-200 bg-emerald-50/40",
      dot: "bg-emerald-500",
    };
  }
  if (status === "needs_setup") {
    return {
      label: "待設定",
      badge: "bg-amber-100 text-amber-800 hover:bg-amber-100",
      tone: "border-amber-200 bg-amber-50/40",
      dot: "bg-amber-500",
    };
  }
  if (status === "planned") {
    return {
      label: "預留",
      badge: "bg-slate-100 text-slate-700 hover:bg-slate-100",
      tone: "border-border bg-card",
      dot: "bg-slate-400",
    };
  }
  return {
    label: "未啟用",
    badge: "",
    tone: "border-border bg-card",
    dot: "bg-slate-400",
  };
}

export function capabilityClass(capability: DataSourceCapability) {
  if (capability.state === "ready") {
    return "border-emerald-200 bg-emerald-50 text-emerald-700";
  }
  if (capability.state === "planned") {
    return "border-slate-200 bg-slate-50 text-slate-600";
  }
  return "border-border bg-muted text-muted-foreground";
}

export function splitCapabilities(source: DataSourceItem) {
  return {
    sourceCapabilities: source.capabilities.filter(
      (capability) => !responseCapabilityKeys.has(capability.key)
    ),
    responseCapabilities: source.capabilities.filter((capability) =>
      responseCapabilityKeys.has(capability.key)
    ),
  };
}

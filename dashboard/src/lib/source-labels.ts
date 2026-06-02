const SOURCE_ALIASES: Record<string, string> = {
  azure_sentinel: "sentinel",
  google: "google_workspace",
  m365: "microsoft_365",
  microsoft365: "microsoft_365",
  ms365: "microsoft_365",
  o365: "microsoft_365",
};

const SOURCE_LABELS: Record<string, string> = {
  elastic: "Elastic",
  google_workspace: "Google Workspace",
  microsoft_365: "Microsoft 365",
  sentinel: "Microsoft Sentinel",
  splunk: "Splunk",
  wazuh: "Wazuh",
  webhook: "Webhook",
};

export function normalizedSourceKey(source?: string | null): string {
  const raw = String(source || "").trim();
  if (!raw) return "wazuh";
  const normalized = raw.toLowerCase().replace(/[\s-]+/g, "_");
  return SOURCE_ALIASES[normalized] || normalized;
}

export function sourceLabel(source?: string | null): string {
  const raw = String(source || "").trim();
  const normalized = normalizedSourceKey(source);
  return SOURCE_LABELS[normalized] || raw;
}

export function hasMultipleSources(sources: Array<string | null | undefined>): boolean {
  return new Set(sources.map((source) => normalizedSourceKey(source))).size > 1;
}

export function shouldShowSourceBadge(
  source?: string | null,
  hasMultipleSourceContext = false
): boolean {
  return hasMultipleSourceContext || normalizedSourceKey(source) !== "wazuh";
}

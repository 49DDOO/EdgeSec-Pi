"use client";

import { Badge } from "@/components/ui/badge";
import { evidenceSummary } from "@/lib/investigation";
import type { InvestigationEvidence } from "@/lib/types";
import { ExpandHint, RotatingChevron } from "./alert-table-model";

const evidenceArgsSummary = (item: InvestigationEvidence) => {
  const entries = Object.entries(item.args || {}).filter(([, value]) => value !== "" && value != null);
  if (!entries.length) return "";
  return entries
    .map(([key, value]) => `${key}=${String(value)}`)
    .join("，");
};

const parseJsonFromText = (value?: string): unknown => {
  const text = String(value || "").trim();
  const start = text.indexOf("{");
  const end = text.lastIndexOf("}");
  if (start < 0 || end <= start) return null;
  try {
    return JSON.parse(text.slice(start, end + 1));
  } catch {
    return null;
  }
};

const toRecord = (value: unknown): Record<string, unknown> =>
  value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};

const parseRuleDetails = (text?: string) => {
  const raw = String(text || "");
  const line = (label: string) => raw.match(new RegExp(`^${label}:\\s*(.+)$`, "m"))?.[1]?.trim() || "";
  const complianceRaw = line("Compliance");
  const compliance = toRecord(parseJsonFromText(complianceRaw));
  const xml = raw.includes("Rule XML:") ? raw.split("Rule XML:", 2)[1].trim() : "";
  return {
    id: line("Rule ID"),
    level: line("Level"),
    description: line("Description"),
    groups: line("Groups"),
    file: line("File"),
    compliance,
    xml,
  };
};

const parseSecurityEvents = (text?: string) => {
  const parsed = toRecord(parseJsonFromText(text));
  const data = toRecord(parsed.data ?? parsed);
  const items = Array.isArray(data.affected_items) ? data.affected_items.map(toRecord) : [];
  return {
    total: Number(data.total_affected_items ?? items.length),
    failed: Number(data.total_failed_items ?? 0),
    items,
  };
};

const compactLog = (value?: unknown, max = 260) => {
  const text = String(value || "").replace(/\\n/g, "\n").trim();
  if (text.length <= max) return text;
  return `${text.slice(0, max)}...`;
};

function RuleDetailsView({ item }: { item: InvestigationEvidence }) {
  const details = parseRuleDetails(item.result_log || item.result_preview);
  if (!details.id && !details.description) {
    return <RawEvidenceText item={item} />;
  }
  return (
    <div className="mt-3 space-y-3 text-xs">
      <div className="grid gap-3 md:grid-cols-4">
        <div>
          <div className="text-muted-foreground">Rule ID</div>
          <div className="mt-1 font-medium">{details.id || "-"}</div>
        </div>
        <div>
          <div className="text-muted-foreground">Level</div>
          <div className="mt-1 font-medium">{details.level || "-"}</div>
        </div>
        <div>
          <div className="text-muted-foreground">Groups</div>
          <div className="mt-1 font-medium">{details.groups || "-"}</div>
        </div>
        <div>
          <div className="text-muted-foreground">規則檔</div>
          <div className="mt-1 break-words font-mono">{details.file || "-"}</div>
        </div>
      </div>
      <div>
        <div className="text-muted-foreground">規則說明</div>
        <div className="mt-1 text-sm">{details.description || "-"}</div>
      </div>
      {Object.keys(details.compliance).length > 0 && (
        <div>
          <div className="text-muted-foreground">合規對應</div>
          <div className="mt-2 flex flex-wrap gap-2">
            {Object.entries(details.compliance).map(([key, value]) => (
              <Badge key={key} variant="secondary" className="font-mono text-xs">
                {key}: {Array.isArray(value) ? value.join(", ") : String(value)}
              </Badge>
            ))}
          </div>
        </div>
      )}
      {details.xml && (
        <details className="rounded-md border bg-muted/30 p-3">
          <summary className="cursor-pointer font-medium">Rule XML 原文</summary>
          <pre className="mt-2 max-h-64 overflow-auto whitespace-pre-wrap break-words font-mono text-xs leading-5 text-muted-foreground">
            {details.xml}
          </pre>
        </details>
      )}
    </div>
  );
}

function SecurityEventsView({ item }: { item: InvestigationEvidence }) {
  const events = parseSecurityEvents(item.result_log || item.result_preview);
  if (!events.items.length && !events.total) {
    return <RawEvidenceText item={item} />;
  }
  return (
    <div className="mt-3 space-y-3 text-xs">
      <div className="grid gap-3 md:grid-cols-3">
        <div>
          <div className="text-muted-foreground">符合事件</div>
          <div className="mt-1 text-lg font-semibold">{events.total}</div>
        </div>
        <div>
          <div className="text-muted-foreground">本次回傳</div>
          <div className="mt-1 text-lg font-semibold">{events.items.length}</div>
        </div>
        <div>
          <div className="text-muted-foreground">查詢失敗</div>
          <div className="mt-1 text-lg font-semibold">{events.failed}</div>
        </div>
      </div>
      <div className="space-y-2">
        {events.items.slice(0, 8).map((event, index) => {
          const agent = toRecord(event.agent);
          const rule = toRecord(event.rule);
          return (
            <div key={`${String(event.timestamp)}-${index}`} className="rounded-md border bg-background p-3">
              <div className="grid gap-2 md:grid-cols-4">
                <div>
                  <div className="text-muted-foreground">時間</div>
                  <div className="mt-1 font-mono">{String(event.timestamp || "-")}</div>
                </div>
                <div>
                  <div className="text-muted-foreground">端點</div>
                  <div className="mt-1 font-medium">{String(agent.name || agent.id || "-")}</div>
                </div>
                <div>
                  <div className="text-muted-foreground">Rule</div>
                  <div className="mt-1 font-medium">
                    {String(rule.id || "-")}
                    {rule.level ? ` / level ${String(rule.level)}` : ""}
                  </div>
                </div>
                <div>
                  <div className="text-muted-foreground">描述</div>
                  <div className="mt-1">{String(rule.description || "-")}</div>
                </div>
              </div>
              {event.full_log ? (
                <pre className="mt-3 whitespace-pre-wrap break-words rounded-md bg-muted/40 p-2 font-mono leading-5 text-muted-foreground">
                  {compactLog(event.full_log)}
                </pre>
              ) : null}
            </div>
          );
        })}
      </div>
      {events.items.length > 8 && (
        <div className="text-muted-foreground">只顯示前 8 筆；完整內容可展開下方原文。</div>
      )}
      <RawEvidenceDetails item={item} />
    </div>
  );
}

function RawEvidenceText({ item }: { item: InvestigationEvidence }) {
  return (
    <pre className="mt-2 max-h-72 overflow-auto whitespace-pre-wrap break-words text-xs leading-5 text-muted-foreground">
      {item.result_log || item.result_preview || "MCP 沒有回傳可顯示的內容。"}
    </pre>
  );
}

function RawEvidenceDetails({ item }: { item: InvestigationEvidence }) {
  return (
    <details className="group rounded-md border bg-background p-3 [&>summary::-webkit-details-marker]:hidden">
      <summary className="flex cursor-pointer list-none items-center justify-between gap-3 text-xs font-medium transition-colors hover:text-foreground">
        <span className="inline-flex items-center gap-2">
          <RotatingChevron />
          查看 MCP 原始回傳
        </span>
        <ExpandHint />
      </summary>
      <RawEvidenceText item={item} />
    </details>
  );
}

function EvidenceResultView({ item }: { item: InvestigationEvidence }) {
  if (item.tool === "get_wazuh_rule_details") return <RuleDetailsView item={item} />;
  if (item.tool === "search_security_events" || item.tool === "get_wazuh_alerts") {
    return <SecurityEventsView item={item} />;
  }
  return <RawEvidenceText item={item} />;
}

export function InvestigationEvidenceList({ evidence }: { evidence: InvestigationEvidence[] }) {
  return (
    <div className="mt-3 space-y-3">
      {evidence.map((item, index) => {
        const argsSummary = evidenceArgsSummary(item);
        return (
          <div key={`${item.tool}-${index}`} className="rounded-md border bg-background p-3">
            <div className="text-xs font-medium text-muted-foreground">
              MCP 工具：{evidenceSummary(item)}
            </div>
            {argsSummary && (
              <div className="mt-1 break-words text-xs text-muted-foreground">
                查詢條件：{argsSummary}
              </div>
            )}
            <EvidenceResultView item={item} />
          </div>
        );
      })}
    </div>
  );
}

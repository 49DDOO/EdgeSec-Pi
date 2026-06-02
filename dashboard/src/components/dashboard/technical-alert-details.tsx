import { Badge } from "@/components/ui/badge";
import type { Alert, TechnicalEvidence } from "@/lib/types";

function valueOrDash(value?: string | number) {
  if (value === 0) return "0";
  return value ? String(value) : "-";
}

function compactIp(value?: string) {
  const ip = String(value || "").trim();
  if (!ip) return "";
  if (/^(?:0{1,4}:){7}0*1$/i.test(ip)) return "::1";
  if (/^(?:0{1,4}:){7}0*0$/i.test(ip)) return "::";
  return ip.replace(/\b0{1,3}([0-9a-f]{1,3})\b/gi, "$1");
}

function isLoopbackIp(value?: string) {
  const ip = compactIp(value).toLowerCase();
  return ip === "127.0.0.1" || ip === "::1" || ip === "localhost";
}

function sourceIpItem(value?: string): [string, string] {
  if (!value) return ["來源 IP", ""];
  if (isLoopbackIp(value)) return ["本機位址", `${compactIp(value)}（不是外部來源）`];
  return ["來源 IP", compactIp(value)];
}

function splitActionLines(text?: string) {
  return String(text || "")
    .split(/\n+/)
    .map((line) => line.replace(/^\s*\d+[.)、]\s*/, "").trim())
    .filter(Boolean);
}

function evidenceItems(alert: Alert) {
  const evidence = alert.technical_evidence;
  if (evidence) {
    const indicators = evidence.indicators || {};
    const endpoint = evidence.endpoint || {};
    const rule = evidence.rule || {};
    const sourceIp = indicators.source_ip || alert.source_ip || "";
    const items = [
      ["SIEM", evidence.source || alert.siem_source || "Wazuh"],
      ["模組", moduleLabel(evidence.module)],
      ["Rule", `${valueOrDash(rule.id)}${rule.level ? ` / level ${rule.level}` : ""}`],
      ["端點", `${endpoint.name || alert.agent_name}${endpoint.ip ? ` / ${endpoint.ip}` : ""}`],
      sourceIpItem(sourceIp),
      ["帳號", indicators.username || ""],
      ["檔案", indicators.file_path || ""],
      ["程序", indicators.process || ""],
      ["Port", indicators.port || ""],
      ["CVE", indicators.cve || ""],
      ["套件", [indicators.package, indicators.package_version].filter(Boolean).join(" ")],
      ["MITRE", (rule.mitre || []).join(", ") || alert.mitre || ""],
    ];
    return items.filter(([, value]) => value && value !== "-");
  }
  const items = [
    ["SIEM", alert.siem_source || "Wazuh"],
    ["Rule", `${valueOrDash(alert.rule_id)}${alert.rule_level ? ` / level ${alert.rule_level}` : ""}`],
    ["端點", `${alert.agent_name}${alert.agent_ip ? ` / ${alert.agent_ip}` : ""}`],
    sourceIpItem(alert.source_ip || ""),
    ["MITRE", alert.mitre || ""],
  ];
  return items.filter(([, value]) => value && value !== "-");
}

function moduleLabel(module?: string) {
  const labels: Record<string, string> = {
    authentication: "登入 / 帳號",
    sca: "安全設定檢查",
    fim: "檔案異動",
    vulnerability: "漏洞訊號",
    rootcheck: "Rootcheck",
    syscollector: "系統盤點",
    windows: "Windows 事件",
    other: "一般事件",
  };
  return labels[module || ""] || module || "一般事件";
}

function remediationText(alert: Alert) {
  const evidence = alert.technical_evidence;
  return evidence?.remediation?.wazuh || evidence?.remediation?.llm || alert.technical_action || alert.recommended_action;
}

function rawLog(alert: Alert) {
  return alert.technical_evidence?.raw?.full_log || alert.full_log;
}

function iocValues(alert: Alert) {
  const indicators = alert.technical_evidence?.indicators;
  return [
    ...(indicators?.iocs || []),
    indicators?.source_ip,
    indicators?.domain,
    indicators?.cve,
    indicators?.file_path,
    ...(indicators?.hashes || []),
    ...(alert.iocs || []),
  ].filter((value, index, arr): value is string => Boolean(value) && !isLoopbackIp(value) && arr.indexOf(value) === index);
}

function ModuleContext({ evidence }: { evidence?: TechnicalEvidence }) {
  const context = evidence?.module_context || {};
  const entries = Object.entries(context).filter(([, value]) => value);
  if (!entries.length) return null;
  const labels: Record<string, string> = {
    check_title: "檢查項目",
    result: "結果",
    description: "檢查說明",
    rationale: "原因",
    checks_condition: "檢查條件",
    checks: "檢查指令",
    compliance: "合規對應",
    remediation: "補強步驟",
    cve: "CVE",
    cvss: "CVSS",
    package: "套件",
    installed_version: "目前版本",
    reference: "參考資料",
    path: "檔案路徑",
    event: "變更類型",
    mode: "模式",
    process: "程序",
    user: "使用者",
    source_ip: "來源 IP",
    username: "帳號",
    authentication_result: "登入結果",
  };
  return (
    <div className="mb-3 rounded-md border bg-background p-3">
      <p className="text-xs font-medium text-muted-foreground">
        {moduleLabel(evidence?.module)}證據
      </p>
      <div className="mt-2 grid gap-2 md:grid-cols-2">
        {entries.map(([key, value]) => (
          <div key={key} className={String(value).length > 80 ? "md:col-span-2" : ""}>
            <p className="text-xs font-medium text-muted-foreground">{labels[key] || key}</p>
            <p className="whitespace-pre-wrap break-words text-xs">{String(value)}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

function FimBrief({ evidence, alert }: { evidence?: TechnicalEvidence; alert: Alert }) {
  const brief = evidence?.fim_brief;
  if (!brief) return null;
  const endpoint = evidence?.endpoint;
  const before = Object.entries(brief.hash_before || {});
  const after = Object.entries(brief.hash_after || {});
  return (
    <div className="mb-3 rounded-md border bg-background p-3">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <p className="text-xs font-medium text-muted-foreground">檔案異動簡報</p>
          <p className="mt-1 text-sm font-semibold">{brief.title_zh}</p>
        </div>
        <Badge variant={brief.severity === "high" ? "destructive" : "secondary"}>
          {brief.severity === "high" ? "高" : brief.severity === "medium" ? "中" : "低"}
        </Badge>
      </div>

      <div className="mt-3 grid gap-3 md:grid-cols-2">
        <div>
          <p className="text-xs font-medium text-muted-foreground">受影響端點</p>
          <p className="text-xs">
            {endpoint?.name || alert.agent_name || "-"}
            {endpoint?.ip || alert.agent_ip ? ` / ${endpoint?.ip || alert.agent_ip}` : ""}
          </p>
          {alert.purpose && <p className="mt-1 text-xs text-muted-foreground">用途：{alert.purpose}</p>}
        </div>
        <div>
          <p className="text-xs font-medium text-muted-foreground">誰改了什麼</p>
          <p className="break-words font-mono text-xs">{brief.file_path}</p>
          <p className="mt-1 text-xs">
            {brief.event_zh}；使用者：{brief.changed_by}；程序：{brief.process}
          </p>
          {brief.changed_at && <p className="text-xs text-muted-foreground">時間：{brief.changed_at}</p>}
        </div>
      </div>

      <div className="mt-3 grid gap-3 md:grid-cols-2">
        <div>
          <p className="text-xs font-medium text-muted-foreground">影響多大</p>
          <p className="text-xs">{brief.business_meaning_zh}</p>
          <p className="mt-1 text-xs">{brief.impact_zh}</p>
        </div>
        <div>
          <p className="text-xs font-medium text-muted-foreground">立刻該做的事</p>
          <ol className="mt-1 list-decimal space-y-1 pl-4 text-xs">
            {brief.recommended_steps_zh.slice(0, 3).map((step) => (
              <li key={step}>{step}</li>
            ))}
          </ol>
        </div>
      </div>

      {(before.length > 0 || after.length > 0 || brief.it_checks.length > 0) && (
        <div className="mt-3 border-t pt-3">
          <p className="text-xs font-medium text-muted-foreground">技術細節</p>
          <div className="mt-2 grid gap-3 md:grid-cols-2">
            {(before.length > 0 || after.length > 0) && (
              <div className="space-y-1">
                {before.map(([kind, value]) => (
                  <p key={`before-${kind}`} className="break-words font-mono text-xs">
                    修改前 {kind}：{value}
                  </p>
                ))}
                {after.map(([kind, value]) => (
                  <p key={`after-${kind}`} className="break-words font-mono text-xs">
                    修改後 {kind}：{value}
                  </p>
                ))}
              </div>
            )}
            {brief.it_checks.length > 0 && (
              <ul className="list-disc space-y-1 pl-4 text-xs">
                {brief.it_checks.slice(0, 4).map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export function TechnicalAlertDetails({ alert, compact = false }: { alert: Alert; compact?: boolean }) {
  const iocs = iocValues(alert);
  const actionLines = splitActionLines(alert.recommended_action || remediationText(alert));

  if (compact) {
    return (
      <div className="text-sm">
        <div className="grid gap-x-8 gap-y-3 md:grid-cols-2">
          {evidenceItems(alert).map(([label, value]) => (
            <div key={label}>
              <p className="text-xs font-medium text-muted-foreground">{label}</p>
              <p className="break-words font-mono text-xs">{value}</p>
            </div>
          ))}
        </div>

        {iocs.length > 0 && (
          <div className="mt-4">
            <p className="text-xs font-medium text-muted-foreground">IOC / 可疑指標</p>
            <div className="mt-1 flex flex-wrap gap-1">
              {iocs.map((ioc) => (
                <Badge key={ioc} variant="secondary" className="font-mono">
                  {ioc}
                </Badge>
              ))}
            </div>
          </div>
        )}

        {(alert.root_cause || alert.technical_action) && (
          <div className="mt-4 grid gap-3 md:grid-cols-2">
            {alert.root_cause && (
              <div>
                <p className="text-xs font-medium text-muted-foreground">判斷原因</p>
                <p className="text-xs">{alert.root_cause}</p>
              </div>
            )}
            {alert.technical_action && (
              <div>
                <p className="text-xs font-medium text-muted-foreground">技術處置原文</p>
                <p className="text-xs">{alert.technical_action}</p>
              </div>
            )}
          </div>
        )}

        {rawLog(alert) && (
          <details className="mt-4">
            <summary className="cursor-pointer text-xs font-medium text-muted-foreground">
              原始 Log
            </summary>
            <pre className="mt-2 max-h-40 overflow-auto rounded-md bg-muted/40 p-2 text-xs">
              {rawLog(alert)}
            </pre>
          </details>
        )}
      </div>
    );
  }

  return (
    <div className="rounded-lg border border-border bg-muted/30 p-3 text-sm">
      <div className="mb-3 flex items-center justify-between gap-3">
        <h4 className="font-semibold">給 IT 的處理單</h4>
        <Badge variant="outline">{alert.siem_source || "Wazuh"}</Badge>
      </div>

      <div className="mb-3 rounded-md border bg-background p-3">
        <p className="text-xs font-medium text-muted-foreground">要查證的問題</p>
        <p className="mt-1 text-sm font-medium">{alert.summary || alert.rule_description}</p>
        {alert.business_impact && (
          <p className="mt-1 text-xs text-muted-foreground">影響：{alert.business_impact}</p>
        )}
      </div>

      {alert.investigation_summary_zh && (
        <div className="mb-3 rounded-md border border-primary/20 bg-primary/5 p-3">
          <p className="text-xs font-medium text-primary">AI 調查說明</p>
          <p className="mt-1 text-sm leading-6">{alert.investigation_summary_zh}</p>
        </div>
      )}

      {actionLines.length > 0 && (
        <div className="mb-3 rounded-md border bg-background p-3">
          <p className="text-xs font-medium text-muted-foreground">建議處理步驟</p>
          <ol className="mt-2 list-decimal space-y-1 pl-5 text-xs">
            {actionLines.slice(0, 5).map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ol>
        </div>
      )}

      <FimBrief evidence={alert.technical_evidence} alert={alert} />

      <ModuleContext evidence={alert.technical_evidence} />

      <div className="grid gap-3 md:grid-cols-2">
        {evidenceItems(alert).map(([label, value]) => (
          <div key={label}>
            <p className="text-xs font-medium text-muted-foreground">{label}</p>
            <p className="break-words font-mono text-xs">{value}</p>
          </div>
        ))}
      </div>

      <div className="mt-3">
        <p className="text-xs font-medium text-muted-foreground">IOC / 可疑指標</p>
        {iocs.length ? (
          <div className="mt-1 flex flex-wrap gap-1">
            {iocs.map((ioc) => (
              <Badge key={ioc} variant="secondary" className="font-mono">
                {ioc}
              </Badge>
            ))}
          </div>
        ) : (
          <p className="text-xs text-muted-foreground">目前沒有明確 IOC</p>
        )}
      </div>

      {(alert.root_cause || alert.technical_action) && (
        <div className="mt-3 grid gap-3 md:grid-cols-2">
          {alert.root_cause && (
            <div>
              <p className="text-xs font-medium text-muted-foreground">判斷原因</p>
              <p className="text-xs">{alert.root_cause}</p>
            </div>
          )}
          {alert.technical_action && (
            <div>
              <p className="text-xs font-medium text-muted-foreground">技術處置原文</p>
              <p className="text-xs">{alert.technical_action}</p>
            </div>
          )}
        </div>
      )}

      {rawLog(alert) && (
        <details className="mt-3" open={!compact}>
          <summary className="cursor-pointer text-xs font-medium text-muted-foreground">
            原始 Log
          </summary>
          <pre className="mt-2 max-h-40 overflow-auto rounded-md bg-background p-2 text-xs">
            {rawLog(alert)}
          </pre>
        </details>
      )}
    </div>
  );
}

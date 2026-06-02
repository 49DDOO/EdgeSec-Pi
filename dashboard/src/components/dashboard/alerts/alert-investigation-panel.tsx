"use client";

import { Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { investigationQuestions } from "@/lib/investigation";
import type { Alert } from "@/lib/types";
import type { InvestigationSession } from "@/lib/use-investigation-sessions";
import { InvestigationEvidenceList } from "./alert-evidence-result";
import { AlertFactGrid } from "./alert-fact-grid";
import {
  currentAlertRawLog,
  ExpandHint,
  expandablePanelClass,
  expandableSummaryClass,
  neutralButtonClass,
  RotatingChevron,
  selectedNeutralButtonClass,
} from "./alert-table-model";

interface InvestigationPanelProps {
  alert: Alert;
  investigationLoading: boolean;
  investigationSession: InvestigationSession;
  relatedIp: string;
  onRunInvestigation: (question: string) => void;
}

export function AlertInvestigationPanel({
  alert,
  investigationLoading,
  investigationSession,
  relatedIp,
  onRunInvestigation,
}: InvestigationPanelProps) {
  return (
    <div className="space-y-4">
      <AlertFactGrid alert={alert} relatedIp={relatedIp} />

      <div className="space-y-4">
        <div className="space-y-2">
          <div className="text-sm font-medium">查證工具列</div>
          <p className="text-xs text-muted-foreground">
            會查證這台端點的歷史軌跡，確認是否有相關異常。
          </p>
          <div className="flex flex-wrap gap-2">
            {investigationQuestions(alert, "analyst").map((question, index) => (
              <Button
                key={question}
                type="button"
                variant="outline"
                size="sm"
                className={index === 0 ? selectedNeutralButtonClass : neutralButtonClass}
                disabled={investigationLoading}
                onClick={() => onRunInvestigation(question)}
              >
                {question}
              </Button>
            ))}
          </div>
        </div>

        <InvestigationHistory
          alert={alert}
          investigationLoading={investigationLoading}
          investigationSession={investigationSession}
        />
      </div>
    </div>
  );
}

function InvestigationHistory({
  alert,
  investigationLoading,
  investigationSession,
}: {
  alert: Alert;
  investigationLoading: boolean;
  investigationSession: InvestigationSession;
}) {
  return (
    <div className="space-y-3">
      <details className={expandablePanelClass}>
        <summary className={expandableSummaryClass}>
          <span className="inline-flex items-center gap-2">
            <RotatingChevron />
            目前這筆事件原始紀錄（已入庫）
          </span>
          <ExpandHint />
        </summary>
        <CurrentAlertRecord alert={alert} />
      </details>

      {investigationSession.messages.length === 0 ? (
        <div className="rounded-lg border border-dashed p-4 text-sm text-muted-foreground">
          尚未啟動證據查詢。上方白話摘要已可先判斷；需要更多線索時再點問題查已接來源。
        </div>
      ) : (
        investigationSession.messages.map((message, index) => (
          <div
            key={`${message.role}-${index}`}
            className={`rounded-lg border p-4 text-sm leading-6 ${
              message.role === "user" ? "bg-muted/40" : "bg-background"
            }`}
          >
            <div className="mb-1 text-xs font-medium text-muted-foreground">
              {message.role === "user" ? "調查問題" : "調查結果"}
            </div>
            <div className="whitespace-pre-line text-[0.95rem] leading-7">
              {message.content}
            </div>
          </div>
        ))
      )}
      {investigationLoading && (
        <div className="flex items-center gap-2 rounded-lg border p-3 text-sm text-muted-foreground">
          <Loader2 className="size-4 animate-spin" />
          正在查詢證據
        </div>
      )}
      {investigationSession.evidence.length > 0 && (
        <details className={expandablePanelClass}>
          <summary className={expandableSummaryClass}>
            <span className="inline-flex items-center gap-2">
              <RotatingChevron />
              證據查詢原始紀錄
            </span>
            <ExpandHint />
          </summary>
          <InvestigationEvidenceList evidence={investigationSession.evidence} />
        </details>
      )}
    </div>
  );
}

function CurrentAlertRecord({ alert }: { alert: Alert }) {
  return (
    <div className="mt-3 space-y-3 text-xs">
      <div className="rounded-md border bg-background p-3">
        <div className="grid gap-3 md:grid-cols-3">
          <div>
            <div className="text-muted-foreground">Rule</div>
            <div className="mt-1 font-medium">
              {alert.rule_id}
              {alert.rule_level != null ? ` / level ${alert.rule_level}` : ""}
            </div>
          </div>
          <div>
            <div className="text-muted-foreground">Agent</div>
            <div className="mt-1 font-medium">
              {alert.agent_name}
              {alert.agent_id ? ` / ${alert.agent_id}` : ""}
            </div>
          </div>
          <div>
            <div className="text-muted-foreground">Agent IP</div>
            <div className="mt-1 font-medium">{alert.agent_ip || "-"}</div>
          </div>
        </div>
        <div className="mt-3">
          <div className="text-muted-foreground">Rule 描述</div>
          <div className="mt-1">{alert.rule_description || "-"}</div>
        </div>
        <div className="mt-3">
          <div className="text-muted-foreground">原始 full_log</div>
          <pre className="mt-1 max-h-56 overflow-auto whitespace-pre-wrap break-words rounded-md bg-muted/40 p-3 leading-5">
            {currentAlertRawLog(alert) || "這筆事件沒有提供 full_log。"}
          </pre>
        </div>
      </div>
    </div>
  );
}

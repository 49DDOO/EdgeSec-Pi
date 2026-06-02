"use client";

import {
  CheckCircle2,
  Loader2,
  Wrench,
  XCircle,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { evidenceSentence, investigationQuestions } from "@/lib/investigation";
import type { InvestigationSession } from "@/lib/use-investigation-sessions";
import {
  getPlainBusinessImpact,
  getPlainLanguageTitle,
} from "./actionable-alert-helpers";
import type { ActionableAlertGroup } from "./actionable-alert-types";

interface ActionableInvestigationSheetProps {
  group: ActionableAlertGroup | null;
  investigationLoading: boolean;
  investigationSession: InvestigationSession;
  onAction: (group: ActionableAlertGroup, action: "it" | "ok" | "false") => void;
  onOpenChange: (open: boolean) => void;
  onRunInvestigation: (question: string) => void;
}

export function ActionableInvestigationSheet({
  group,
  investigationLoading,
  investigationSession,
  onAction,
  onOpenChange,
  onRunInvestigation,
}: ActionableInvestigationSheetProps) {
  const investigatingAlert = group?.primary;
  const investigatingCount = group?.alerts.length || 0;

  return (
    <Sheet
      open={Boolean(group)}
      onOpenChange={onOpenChange}
    >
      <SheetContent className="w-[min(720px,calc(100vw-1rem))] gap-0 p-0 sm:max-w-none">
        <SheetHeader className="border-b pr-12">
          <SheetTitle>證據查詢</SheetTitle>
          <SheetDescription>
            事件已先由 LLM 翻成白話；需要更多線索時，才從這裡讀取已接來源的證據。
          </SheetDescription>
        </SheetHeader>

        {investigatingAlert && group && (
          <div className="flex min-h-0 flex-1 flex-col">
            <div className="space-y-4 overflow-auto p-4">
              <div className="rounded-lg border bg-muted/40 p-4">
                <div className="text-xs font-medium text-muted-foreground">LLM 白話摘要</div>
                <div className="mt-1 text-base font-semibold">
                  {getPlainLanguageTitle(investigatingAlert)}
                </div>
                <div className="mt-2 text-sm leading-6 text-muted-foreground">
                  {getPlainBusinessImpact(investigatingAlert)}
                </div>
                <div className="mt-3 grid gap-3 text-sm sm:grid-cols-2">
                  <div>
                    <div className="text-xs text-muted-foreground">端點</div>
                    <div>{investigatingAlert.agent_name}</div>
                  </div>
                  <div>
                    <div className="text-xs text-muted-foreground">時間</div>
                    <div>
                      {new Intl.DateTimeFormat("zh-TW", {
                        month: "2-digit",
                        day: "2-digit",
                        hour: "2-digit",
                        minute: "2-digit",
                        hour12: false,
                      }).format(new Date(investigatingAlert.timestamp))}
                    </div>
                  </div>
                  <div>
                    <div className="text-xs text-muted-foreground">Rule</div>
                    <div>
                      {investigatingAlert.rule_id}
                      {investigatingAlert.rule_level != null ? ` / level ${investigatingAlert.rule_level}` : ""}
                    </div>
                  </div>
                  <div>
                    <div className="text-xs text-muted-foreground">狀態</div>
                    <div>{investigatingCount > 1 ? `同類 ${investigatingCount} 筆待確認` : "待確認"}</div>
                  </div>
                </div>
              </div>

              <div className="rounded-lg border border-amber-200 bg-amber-50 p-3 text-sm leading-6 text-amber-950 dark:border-amber-900/50 dark:bg-amber-950/20 dark:text-amber-100">
                證據查詢是按需工具。點下方問題後才會讀取已接來源的紀錄，目前主要查 Wazuh MCP；這裡不會封鎖、隔離、停用帳號或修改設定。
              </div>

              <div className="space-y-2">
                <div className="text-sm font-medium">先問這幾個問題</div>
                <div className="flex flex-wrap gap-2">
                  {investigationQuestions(investigatingAlert).map((question) => (
                    <Button
                      key={question}
                      type="button"
                      variant="outline"
                      size="sm"
                      disabled={investigationLoading}
                      onClick={() => void onRunInvestigation(question)}
                    >
                      {question}
                    </Button>
                  ))}
                </div>
              </div>

              <div className="space-y-3">
                {investigationSession.messages.length === 0 ? (
                  <div className="rounded-lg border border-dashed p-4 text-sm text-muted-foreground">
                    尚未啟動證據查詢。上方白話摘要已可先判斷；需要更多線索時再點問題查已接來源。
                  </div>
                ) : (
                  investigationSession.messages.map((message, index) => (
                    <div
                      key={`${message.role}-${index}`}
                      className={`rounded-lg border p-3 text-sm leading-6 ${
                        message.role === "user" ? "bg-muted/50" : "bg-background"
                      }`}
                    >
                      <div className="mb-1 text-xs font-medium text-muted-foreground">
                        {message.role === "user" ? "調查問題" : "調查結果"}
                      </div>
                      <div className="whitespace-pre-line">{message.content}</div>
                    </div>
                  ))
                )}
                {investigationLoading && (
                  <div className="flex items-center gap-2 rounded-lg border p-3 text-sm text-muted-foreground">
                    <Loader2 className="size-4 animate-spin" />
                    正在查詢證據
                  </div>
                )}
              </div>

              {investigationSession.evidence.length > 0 && (
                <details className="rounded-lg border p-3">
                  <summary className="cursor-pointer text-sm font-medium">證據查詢紀錄</summary>
                  <div className="mt-3 space-y-2">
                    {investigationSession.evidence.map((item, index) => (
                      <div key={`${item.tool}-${index}`} className="rounded-md border bg-muted/30 p-3 text-xs">
                        <div className="font-medium">{evidenceSentence(item)}</div>
                        <pre className="mt-2 max-h-28 overflow-auto whitespace-pre-wrap text-muted-foreground">
                          {JSON.stringify(item.args || {}, null, 2)}
                          {"\n\n"}
                          {item.result_preview || ""}
                        </pre>
                      </div>
                    ))}
                  </div>
                </details>
              )}
            </div>

            <SheetFooter className="border-t bg-card sm:flex-row sm:justify-between">
              <div className="flex flex-wrap gap-2">
                <Button
                  onClick={() => {
                    onAction(group, "it");
                    onOpenChange(false);
                  }}
                  className="gap-1"
                >
                  <Wrench data-icon="inline-start" />
                  交給 IT 處理
                </Button>
                <Button
                  variant="outline"
                  onClick={() => {
                    onAction(group, "ok");
                    onOpenChange(false);
                  }}
                >
                  <CheckCircle2 data-icon="inline-start" />
                  確認正常
                </Button>
                <Button
                  variant="outline"
                  onClick={() => {
                    onAction(group, "false");
                    onOpenChange(false);
                  }}
                >
                  <XCircle data-icon="inline-start" />
                  標記誤報
                </Button>
              </div>
              <Button variant="ghost" onClick={() => onOpenChange(false)}>
                回到待辦
              </Button>
            </SheetFooter>
          </div>
        )}
      </SheetContent>
    </Sheet>
  );
}

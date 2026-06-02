"use client";

import {
  CheckCircle2,
  ExternalLink,
  Search,
  Wrench,
  XCircle,
} from "lucide-react";
import { Button, buttonVariants } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import type { ActionableAlertGroup } from "./actionable-alert-types";

interface ActionableAlertActionsProps {
  group: ActionableAlertGroup;
  onAction: (group: ActionableAlertGroup, action: "it" | "ok" | "false") => void;
  onOpenInvestigation: (group: ActionableAlertGroup) => void;
}

export function ActionableAlertActions({
  group,
  onAction,
  onOpenInvestigation,
}: ActionableAlertActionsProps) {
  const alert = group.primary;

  return (
    <div className="flex flex-wrap gap-2">
      <Button
        type="button"
        variant="secondary"
        size="sm"
        onClick={() => onOpenInvestigation(group)}
        className="gap-1"
      >
        <Search data-icon="inline-start" />
        查證證據
      </Button>
      <Button
        size="sm"
        onClick={() => onAction(group, "it")}
        className="gap-1"
      >
        <Wrench data-icon="inline-start" />
        交給 IT 處理
      </Button>
      <Button
        size="sm"
        variant="outline"
        onClick={() => onAction(group, "ok")}
        className="gap-1"
      >
        <CheckCircle2 data-icon="inline-start" />
        確認為正常
      </Button>
      <Button
        size="sm"
        variant="ghost"
        onClick={() => onAction(group, "false")}
        className="gap-1 text-muted-foreground"
      >
        <XCircle data-icon="inline-start" />
        標記誤報
      </Button>
      <a
        href={`/events?alert=${encodeURIComponent(alert.id)}`}
        className={cn(
          buttonVariants({ variant: "link", size: "sm" }),
          "gap-1 px-1 text-muted-foreground"
        )}
      >
        <ExternalLink data-icon="inline-start" />
        查看完整事件
      </a>
    </div>
  );
}

"use client";

import { CircleHelp, Save } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Switch } from "@/components/ui/switch";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import type { DetectionCategory, DetectionCategoryKey } from "@/lib/types";

interface DetectionCategoryListProps {
  categories: DetectionCategory[];
  enabled: Record<DetectionCategoryKey, boolean>;
  enabledCount: number;
  coreEnabledCount: number;
  saving: boolean;
  onToggleCategory: (key: DetectionCategoryKey, value: boolean) => void;
  onSave: () => void;
}

export function DetectionCategoryList({
  categories,
  enabled,
  enabledCount,
  coreEnabledCount,
  saving,
  onToggleCategory,
  onSave,
}: DetectionCategoryListProps) {
  return (
    <Card className="mt-4">
      <CardHeader>
        <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
          <div>
            <CardTitle>事件中心訊號</CardTitle>
            <CardDescription>
              啟用代表顯示在 Dashboard 並送 LLM 解析；關閉代表只入庫留存，降低本機模型負載。
            </CardDescription>
          </div>
          <Badge variant="secondary">{enabledCount} / {categories.length} 已啟用</Badge>
        </div>
      </CardHeader>
      <CardContent>
        <div className="divide-y divide-border">
          {categories.map((category) => (
            <div
              key={category.key}
              className="flex items-center justify-between gap-4 py-4 first:pt-0"
            >
              <div className="min-w-0">
                <div className="flex items-center gap-2 font-medium">
                  <span>{category.label_zh}</span>
                  {category.detail_zh && (
                    <Tooltip>
                      <TooltipTrigger
                        render={
                          <button
                            type="button"
                            className="inline-flex size-6 items-center justify-center rounded-full text-muted-foreground hover:bg-muted hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                            aria-label={`${category.label_zh} 說明`}
                          >
                            <CircleHelp className="size-4" />
                          </button>
                        }
                      />
                      <TooltipContent
                        side="right"
                        align="start"
                        className="max-w-sm whitespace-normal text-left leading-relaxed"
                      >
                        {category.detail_zh}
                      </TooltipContent>
                    </Tooltip>
                  )}
                </div>
                <p className="mt-1 text-sm text-muted-foreground">
                  {category.description_zh}
                </p>
              </div>
              <Switch
                checked={enabled[category.key]}
                onCheckedChange={(value) => onToggleCategory(category.key, Boolean(value))}
                aria-label={`切換 ${category.label_zh}`}
              />
            </div>
          ))}
        </div>

        <div className="mt-4 flex justify-end">
          <Button
            type="button"
            onClick={onSave}
            disabled={saving || enabledCount === 0 || coreEnabledCount === 0}
          >
            <Save data-icon="inline-start" />
            儲存設定
          </Button>
        </div>
        {enabledCount === 0 && (
          <p className="text-sm text-destructive">
            至少保留一個類別，否則事件中心不會顯示任何事件。
          </p>
        )}
        {enabledCount > 0 && coreEnabledCount === 0 && (
          <p className="text-sm text-destructive">
            至少保留一個核心資安訊號類別，避免只留下低信號噪音。
          </p>
        )}
      </CardContent>
    </Card>
  );
}

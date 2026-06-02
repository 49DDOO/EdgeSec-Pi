"use client";

import { AlertTriangle, CheckCircle2 } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { coreSignalKeys, type DetectionDraftProfile } from "./detection-settings-model";

interface DetectionNoisePanelProps {
  profile: DetectionDraftProfile;
  falsePositiveSuppression: boolean;
}

export function DetectionNoisePanel({
  profile,
  falsePositiveSuppression,
}: DetectionNoisePanelProps) {
  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between gap-3">
          <div>
            <CardTitle>噪音保護</CardTitle>
            <CardDescription>
              類別開大時，先確認是否有抑制與核心訊號保留。
            </CardDescription>
          </div>
          {profile.warnings.length ? (
            <AlertTriangle className="size-5 text-amber-500" />
          ) : (
            <CheckCircle2 className="size-5 text-success" />
          )}
        </div>
      </CardHeader>
      <CardContent className="space-y-4 text-sm">
        <div>
          <div className="text-xs text-muted-foreground">FP suppression</div>
          <div className="mt-1 font-medium">
            {falsePositiveSuppression ? "已啟用" : "未啟用"}
          </div>
        </div>
        <div>
          <div className="text-xs text-muted-foreground">高噪音類別</div>
          <div className="mt-2 flex flex-wrap gap-2">
            {profile.noisyEnabled.length ? profile.noisyEnabled.map((category) => (
              <Badge key={category.key} variant="outline">{category.label_zh}</Badge>
            )) : <span className="text-muted-foreground">目前未啟用</span>}
          </div>
        </div>
        <div>
          <div className="text-xs text-muted-foreground">核心訊號</div>
          <div className="mt-1 font-medium">
            {profile.coreEnabledCount} / {coreSignalKeys.size} 已啟用
          </div>
        </div>
        {profile.warnings.length > 0 && (
          <div className="space-y-2 rounded-md border border-amber-200 bg-amber-50 p-3 text-amber-800 dark:border-amber-900 dark:bg-amber-950/30 dark:text-amber-200">
            {profile.warnings.map((warning) => (
              <div key={warning}>{warning}</div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

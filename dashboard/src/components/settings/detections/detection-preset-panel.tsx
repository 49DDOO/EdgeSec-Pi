"use client";

import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import type { DetectionPreset, DetectionPresetKey } from "@/lib/types";
import { noiseLevelLabel } from "./detection-settings-model";

interface DetectionPresetPanelProps {
  activePreset: DetectionPresetKey;
  presets: DetectionPreset[];
  loading: boolean;
  saving: boolean;
  onApplyPreset: (preset: DetectionPreset) => void;
}

export function DetectionPresetPanel({
  activePreset,
  presets,
  loading,
  saving,
  onApplyPreset,
}: DetectionPresetPanelProps) {
  const activeLabel = activePreset === "custom"
    ? "自訂"
    : presets.find((preset) => preset.key === activePreset)?.label_zh;

  return (
    <Card>
      <CardHeader>
        <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
          <div>
            <CardTitle>偵測 Preset</CardTitle>
            <CardDescription>
              先用 preset 決定覆蓋範圍，再針對實際噪音調整類別。
            </CardDescription>
          </div>
          <Badge variant={activePreset === "custom" ? "outline" : "secondary"}>
            {activeLabel}
          </Badge>
        </div>
      </CardHeader>
      <CardContent>
        <div className="grid gap-3 md:grid-cols-3">
          {presets.map((preset) => {
            const selected = activePreset === preset.key;
            return (
              <button
                key={preset.key}
                type="button"
                onClick={() => onApplyPreset(preset)}
                disabled={loading || saving}
                className={[
                  "rounded-lg border p-4 text-left transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
                  selected ? "border-foreground bg-muted" : "border-border bg-background hover:bg-muted/50",
                ].join(" ")}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="font-medium">{preset.label_zh}</span>
                  <Badge variant={selected ? "default" : "outline"}>
                    {noiseLevelLabel[preset.noise_level]}
                  </Badge>
                </div>
                <p className="mt-2 text-sm leading-6 text-muted-foreground">
                  {preset.description_zh}
                </p>
              </button>
            );
          })}
        </div>
      </CardContent>
    </Card>
  );
}

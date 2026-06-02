import type {
  DetectionCategory,
  DetectionCategoryKey,
  DetectionPreset,
} from "@/lib/types";

export const noisyCategoryKeys = new Set<DetectionCategoryKey>([
  "sca",
  "network",
  "system",
  "compliance",
  "other",
]);

export const coreSignalKeys = new Set<DetectionCategoryKey>([
  "authentication",
  "vulnerability",
  "fim",
  "process",
  "malware",
]);

export const noiseLevelLabel: Record<DetectionPreset["noise_level"], string> = {
  low: "低噪音",
  medium: "中噪音",
  high: "高覆蓋",
};

export interface DetectionDraftProfile {
  enabledCount: number;
  coreEnabledCount: number;
  noisyEnabled: DetectionCategory[];
  coreDisabled: DetectionCategory[];
  warnings: string[];
}

export function detectionDraftProfile(
  categories: DetectionCategory[],
  enabled: Record<DetectionCategoryKey, boolean>,
  falsePositiveSuppression = true
): DetectionDraftProfile {
  const enabledCount = categories.filter((category) => enabled[category.key]).length;
  const coreEnabledCount = categories.filter((category) => (
    coreSignalKeys.has(category.key) && enabled[category.key]
  )).length;
  const noisyEnabled = categories.filter((category) => (
    noisyCategoryKeys.has(category.key) && enabled[category.key]
  ));
  const coreDisabled = categories.filter((category) => (
    coreSignalKeys.has(category.key) && !enabled[category.key]
  ));
  const warnings = [
    ...(noisyEnabled.length > 0 && !falsePositiveSuppression
      ? ["已啟用高噪音類別，但 FP suppression 目前關閉。"]
      : []),
    ...(coreDisabled.length > 0 ? ["部分核心資安訊號目前關閉。"] : []),
    ...(noisyEnabled.length >= 4 ? ["高噪音類別開啟較多，請留意事件量與本機 LLM 延遲。"] : []),
  ];

  return {
    enabledCount,
    coreEnabledCount,
    noisyEnabled,
    coreDisabled,
    warnings,
  };
}

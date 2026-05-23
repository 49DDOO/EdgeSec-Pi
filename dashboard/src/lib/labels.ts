import type { AlertStatus, SeverityLevel } from "@/lib/types";

export const severityLabels: Record<SeverityLevel | "normal", string> = {
  critical: "危急",
  high: "高風險",
  medium: "中風險",
  low: "低風險",
  normal: "正常",
};

export const statusLabels: Record<AlertStatus, string> = {
  pending: "待處理",
  acknowledged: "已確認",
  resolved: "已解決",
  false_positive: "誤報",
};

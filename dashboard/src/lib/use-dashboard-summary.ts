"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { toast } from "sonner";
import { fetchDashboardSummary, updateAlertStatus, type DashboardSummary } from "@/lib/api";
import { filterAlertsByEnabledCategories } from "@/lib/detection-categories";
import type { AlertStatus } from "@/lib/types";

// 資安面板需要近即時更新：預設每 15 秒輪詢一次 bridge。
const POLL_INTERVAL_MS = 15_000;

export interface UseDashboardSummaryOptions {
  /** 輪詢間隔（毫秒）。傳入 0 可停用輪詢，只抓一次。 */
  pollIntervalMs?: number;
}

export interface UseDashboardSummaryResult {
  summary: DashboardSummary | null;
  visibleAlerts: ReturnType<typeof filterAlertsByEnabledCategories>;
  /** 僅在「從未成功取得任何資料」時為非 null。已有 stale 資料時不會清空畫面。 */
  loadError: string | null;
  /** 目前顯示的是否為過期（連線中斷後保留的）資料。 */
  isStale: boolean;
  /** 最後一次成功取得資料的時間。 */
  lastUpdatedAt: Date | null;
  handleStatusChange: (alertId: string, newStatus: AlertStatus) => Promise<void>;
  /** 手動觸發重新抓取（例如使用者按重試）。 */
  refresh: () => void;
}

export function useDashboardSummary(
  options: UseDashboardSummaryOptions = {}
): UseDashboardSummaryResult {
  const { pollIntervalMs = POLL_INTERVAL_MS } = options;

  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [isStale, setIsStale] = useState(false);
  const [lastUpdatedAt, setLastUpdatedAt] = useState<Date | null>(null);

  // 用 ref 追蹤是否已掛載，避免卸載後 setState；並讓輪詢能讀到目前是否有資料。
  const activeRef = useRef(true);
  const hasDataRef = useRef(false);
  const [refreshNonce, setRefreshNonce] = useState(0);

  const load = useCallback(async () => {
    try {
      const data = await fetchDashboardSummary();
      if (!activeRef.current) return;
      hasDataRef.current = true;
      setSummary(data);
      setLoadError(null);
      setIsStale(false);
      setLastUpdatedAt(new Date());
    } catch (error) {
      if (!activeRef.current) return;
      const message = error instanceof Error ? error.message : "Dashboard API 無法連線";
      // 已有資料時：保留畫面、標記為過期，不要把整頁清空。
      if (hasDataRef.current) {
        setIsStale(true);
      } else {
        setLoadError(message);
      }
    }
  }, []);

  useEffect(() => {
    activeRef.current = true;
    const initialLoad = window.setTimeout(() => {
      void load();
    }, 0);

    let timer: ReturnType<typeof setInterval> | undefined;
    if (pollIntervalMs > 0) {
      timer = setInterval(() => {
        void load();
      }, pollIntervalMs);
    }

    return () => {
      activeRef.current = false;
      window.clearTimeout(initialLoad);
      if (timer) clearInterval(timer);
    };
  }, [load, pollIntervalMs, refreshNonce]);

  const refresh = useCallback(() => {
    setRefreshNonce((value) => value + 1);
  }, []);

  const visibleAlerts = useMemo(
    () => summary
      ? filterAlertsByEnabledCategories(summary.alerts, summary.detectionCategories)
      : [],
    [summary]
  );

  const handleStatusChange = useCallback(async (alertId: string, newStatus: AlertStatus) => {
    // 樂觀更新：只記住「這一筆」的原值，避免並發點擊時 rollback 把其他變更一起還原。
    let previousStatus: AlertStatus | undefined;
    setSummary((prev) => {
      if (!prev) return prev;
      return {
        ...prev,
        alerts: prev.alerts.map((alert) => {
          if (alert.id !== alertId) return alert;
          previousStatus = alert.status;
          return { ...alert, status: newStatus };
        }),
      };
    });

    try {
      await updateAlertStatus(alertId, newStatus);
    } catch (error) {
      // 僅還原這一筆告警，保留期間其他告警的更新與輪詢進來的新資料。
      setSummary((prev) => {
        if (!prev || previousStatus === undefined) return prev;
        return {
          ...prev,
          alerts: prev.alerts.map((alert) =>
            alert.id === alertId ? { ...alert, status: previousStatus as AlertStatus } : alert
          ),
        };
      });
      toast.error("狀態更新失敗", {
        description: error instanceof Error ? error.message : "請確認橋接服務是否正常",
      });
    }
  }, []);

  return {
    summary,
    visibleAlerts,
    loadError,
    isStale,
    lastUpdatedAt,
    handleStatusChange,
    refresh,
  };
}

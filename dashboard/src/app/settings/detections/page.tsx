"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { RefreshCw, Save } from "lucide-react";
import { toast } from "sonner";
import { ThemeToggle } from "@/components/dashboard/theme-toggle";
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
  fetchDetectionCategorySettings,
  saveDetectionCategorySettings,
} from "@/lib/api";
import { normalizedDetectionSettings } from "@/lib/detection-categories";
import type { DetectionCategoryKey, DetectionCategorySettings } from "@/lib/types";

export default function DetectionSettingsPage() {
  const [settings, setSettings] = useState<DetectionCategorySettings | null>(null);
  const [draft, setDraft] = useState<Record<DetectionCategoryKey, boolean> | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  const normalized = useMemo(
    () => normalizedDetectionSettings(settings || undefined),
    [settings]
  );
  const activeDraft = draft || normalized.enabled;
  const enabledCount = normalized.categories.filter((category) => activeDraft[category.key]).length;

  const loadSettings = useCallback(async (showToast = false) => {
    setLoading(true);
    try {
      const next = normalizedDetectionSettings(await fetchDetectionCategorySettings());
      setSettings(next);
      setDraft(next.enabled);
      if (showToast) toast.success("偵測類別設定已重新載入");
    } catch (error) {
      toast.error("讀取失敗", {
        description: error instanceof Error ? error.message : String(error),
      });
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    let active = true;
    fetchDetectionCategorySettings()
      .then((nextSettings) => {
        if (!active) return;
        const next = normalizedDetectionSettings(nextSettings);
        setSettings(next);
        setDraft(next.enabled);
      })
      .catch((error) => {
        if (!active) return;
        toast.error("讀取失敗", {
          description: error instanceof Error ? error.message : String(error),
        });
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, []);

  const toggleCategory = (key: DetectionCategoryKey, value: boolean) => {
    setDraft((current) => ({
      ...(current || normalized.enabled),
      [key]: value,
    }));
  };

  const saveSettings = async () => {
    if (!draft) return;
    setSaving(true);
    try {
      const next = normalizedDetectionSettings(await saveDetectionCategorySettings(draft));
      setSettings(next);
      setDraft(next.enabled);
      toast.success(next.message || "偵測類別設定已儲存");
    } catch (error) {
      toast.error("儲存失敗", {
        description: error instanceof Error ? error.message : String(error),
      });
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="flex h-full flex-col">
      <header className="flex items-center justify-between border-b border-border bg-card px-6 py-4">
        <div>
          <h1 className="text-xl font-semibold">偵測類別</h1>
          <p className="text-sm text-muted-foreground">
            關閉類別時仍會保存原始 Log，但新告警不送 LLM 深度解析，也不在預設告警紀錄顯示。
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={() => void loadSettings(true)}
            disabled={loading || saving}
          >
            <RefreshCw data-icon="inline-start" className={loading ? "animate-spin" : ""} />
            重新載入
          </Button>
          <ThemeToggle />
        </div>
      </header>

      <main className="flex-1 overflow-auto p-6">
        <Card>
          <CardHeader>
            <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
              <div>
                <CardTitle>告警紀錄分頁</CardTitle>
                <CardDescription>
                  啟用代表顯示在 Dashboard 並送 LLM 解析；關閉代表只入庫留存，降低本機模型負載。
                </CardDescription>
              </div>
              <Badge variant="secondary">{enabledCount} / {normalized.categories.length} 已啟用</Badge>
            </div>
          </CardHeader>
          <CardContent>
            <div className="divide-y divide-border">
              {normalized.categories.map((category) => {
                const checked = activeDraft[category.key];
                return (
                  <div
                    key={category.key}
                    className="flex items-center justify-between gap-4 py-4 first:pt-0"
                  >
                    <div className="min-w-0">
                      <div className="font-medium">{category.label_zh}</div>
                      <p className="mt-1 text-sm text-muted-foreground">
                        {category.description_zh}
                      </p>
                    </div>
                    <Switch
                      checked={checked}
                      onCheckedChange={(value) => toggleCategory(category.key, Boolean(value))}
                      aria-label={`切換 ${category.label_zh}`}
                    />
                  </div>
                );
              })}
            </div>

            <div className="mt-4 flex justify-end">
              <Button
                type="button"
                onClick={() => void saveSettings()}
                disabled={!draft || saving || enabledCount === 0}
              >
                <Save data-icon="inline-start" />
                儲存設定
              </Button>
            </div>
            {enabledCount === 0 && (
              <p className="text-sm text-destructive">
                至少保留一個類別，否則告警紀錄不會顯示任何事件。
              </p>
            )}
          </CardContent>
        </Card>
      </main>
    </div>
  );
}

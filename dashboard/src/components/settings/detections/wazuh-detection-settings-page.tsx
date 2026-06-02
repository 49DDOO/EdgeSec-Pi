"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { RefreshCw, SlidersHorizontal } from "lucide-react";
import { toast } from "sonner";
import { PageHeader } from "@/components/dashboard/page-header";
import { DetectionCategoryList } from "@/components/settings/detections/detection-category-list";
import { DetectionNoisePanel } from "@/components/settings/detections/detection-noise-panel";
import { DetectionPresetPanel } from "@/components/settings/detections/detection-preset-panel";
import { detectionDraftProfile } from "@/components/settings/detections/detection-settings-model";
import { Button } from "@/components/ui/button";
import {
  fetchDetectionCategorySettings,
  saveDetectionCategorySettings,
} from "@/lib/api";
import { normalizedDetectionSettings } from "@/lib/detection-categories";
import type {
  DetectionCategoryKey,
  DetectionCategorySettings,
  DetectionPreset,
  DetectionPresetKey,
} from "@/lib/types";

export function WazuhDetectionSettingsPage() {
  const [settings, setSettings] = useState<DetectionCategorySettings | null>(null);
  const [draft, setDraft] = useState<Record<DetectionCategoryKey, boolean> | null>(null);
  const [draftPreset, setDraftPreset] = useState<DetectionPresetKey>("custom");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  const normalized = useMemo(
    () => normalizedDetectionSettings(settings || undefined),
    [settings]
  );
  const activeDraft = draft || normalized.enabled;
  const draftProfile = detectionDraftProfile(
    normalized.categories,
    activeDraft,
    normalized.noise?.false_positive_suppression !== false
  );

  const loadSettings = useCallback(async (showToast = false) => {
    setLoading(true);
    try {
      const next = normalizedDetectionSettings(await fetchDetectionCategorySettings());
      setSettings(next);
      setDraft(next.enabled);
      setDraftPreset(next.active_preset || "custom");
      if (showToast) toast.success("Wazuh 訊號類別已重新載入");
    } catch (error) {
      toast.error("讀取 Wazuh 訊號類別失敗", {
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
        setDraftPreset(next.active_preset || "custom");
      })
      .catch((error) => {
        if (!active) return;
        toast.error("讀取 Wazuh 訊號類別失敗", {
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
    setDraftPreset("custom");
  };

  const applyPreset = (preset: DetectionPreset) => {
    setDraft(preset.enabled);
    setDraftPreset(preset.key);
  };

  const saveSettings = async () => {
    if (!draft) return;
    setSaving(true);
    try {
      const next = normalizedDetectionSettings(await saveDetectionCategorySettings(draft, draftPreset));
      setSettings(next);
      setDraft(next.enabled);
      setDraftPreset(next.active_preset || "custom");
      toast.success(next.message || "Wazuh 訊號類別已儲存");
    } catch (error) {
      toast.error("儲存 Wazuh 訊號類別失敗", {
        description: error instanceof Error ? error.message : String(error),
      });
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="flex h-full flex-col">
      <PageHeader
        icon={SlidersHorizontal}
        title="Wazuh 訊號類別"
        description="這是 Wazuh Alert 來源的分類與噪音控制；關閉類別時仍保存原始紀錄，但新事件不送 LLM 深度解析，也不在事件中心預設顯示。"
        actions={
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
        }
      />

      <main className="flex-1 overflow-auto p-6">
        <div className="mb-4 rounded-lg border bg-muted/40 px-4 py-3 text-sm text-muted-foreground">
          這些分類對應 Wazuh 的 rule groups、SCA、FIM/syscheck、Vulnerability Detection、
          rootcheck、登入與系統狀態事件。未來其他來源會有自己的訊號分類，不共用這份 Wazuh 設定。
        </div>

        <div className="grid gap-4 xl:grid-cols-[minmax(0,2fr)_minmax(320px,1fr)]">
          <DetectionPresetPanel
            activePreset={draftPreset}
            presets={normalized.presets || []}
            loading={loading}
            saving={saving}
            onApplyPreset={applyPreset}
          />

          <DetectionNoisePanel
            profile={draftProfile}
            falsePositiveSuppression={normalized.noise?.false_positive_suppression !== false}
          />
        </div>

        <DetectionCategoryList
          categories={normalized.categories}
          enabled={activeDraft}
          enabledCount={draftProfile.enabledCount}
          coreEnabledCount={draftProfile.coreEnabledCount}
          saving={saving}
          onToggleCategory={toggleCategory}
          onSave={() => void saveSettings()}
        />
      </main>
    </div>
  );
}

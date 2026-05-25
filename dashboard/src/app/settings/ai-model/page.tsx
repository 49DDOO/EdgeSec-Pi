"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { BrainCircuit, Save, TestTube, KeyRound } from "lucide-react";
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
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import {
  fetchAiModels,
  fetchAiSettings,
  saveAiSettings,
  testAiSettings,
  useAiProvider as activateAiProvider,
} from "@/lib/api";
import type { AiProviderKey, AiProviderOption, AiSettings } from "@/lib/types";

interface Draft {
  enabled: boolean;
  provider: AiProviderKey;
  base_url: string;
  model: string;
  api_key: string;
  clear_api_key: boolean;
  timeout_s: number;
  max_concurrent_requests: number;
}

function draftFromProvider(settings: AiSettings, providerKey = settings.active_provider): Draft {
  const provider = settings.providers.find((item) => item.key === providerKey) || settings.providers[0];
  return {
    enabled: settings.enabled,
    provider: provider.key,
    base_url: provider.base_url,
    model: provider.model,
    api_key: "",
    clear_api_key: false,
    timeout_s: provider.timeout_s,
    max_concurrent_requests: provider.max_concurrent_requests,
  };
}

function providerMatchesDraft(provider: AiProviderOption | undefined, draft: Draft | null) {
  if (!provider || !draft) return false;
  return (
    provider.base_url === draft.base_url &&
    provider.model === draft.model &&
    provider.timeout_s === draft.timeout_s &&
    provider.max_concurrent_requests === draft.max_concurrent_requests &&
    !draft.api_key &&
    !draft.clear_api_key
  );
}

export default function AiModelSettingsPage() {
  const [settings, setSettings] = useState<AiSettings | null>(null);
  const [draft, setDraft] = useState<Draft | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [savingEnabled, setSavingEnabled] = useState(false);
  const [usingProvider, setUsingProvider] = useState(false);
  const [testing, setTesting] = useState(false);
  const [loadingModels, setLoadingModels] = useState(false);
  const [modelOptions, setModelOptions] = useState<string[]>([]);
  const [modelHint, setModelHint] = useState("正在讀取模型清單...");

  const editingProvider = useMemo(
    () => settings?.providers.find((provider) => provider.key === draft?.provider),
    [draft?.provider, settings?.providers]
  );
  const activeProvider = useMemo(
    () => settings?.providers.find((provider) => provider.key === settings.active_provider),
    [settings]
  );
  const hasUnsavedProviderChanges = !providerMatchesDraft(editingProvider, draft);

  useEffect(() => {
    let active = true;
    fetchAiSettings()
      .then((next) => {
        if (!active) return;
        setSettings(next);
        setDraft(draftFromProvider(next));
      })
      .catch((error) => {
        if (!active) return;
        toast.error("讀取 AI模型設定失敗", {
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

  function updateDraft<K extends keyof Draft>(key: K, value: Draft[K]) {
    setDraft((current) => (current ? { ...current, [key]: value } : current));
  }

  function selectProvider(provider: AiProviderKey) {
    if (!settings) return;
    setDraft(draftFromProvider(settings, provider));
    setModelOptions([]);
    setModelHint("正在讀取模型清單...");
  }

  async function handleSave() {
    if (!draft) return;
    setSaving(true);
    try {
      const next = await saveAiSettings(draft);
      setSettings(next);
      setDraft(draftFromProvider(next, draft.provider));
      toast.success(next.message || "模型設定已儲存");
    } catch (error) {
      toast.error("儲存失敗", {
        description: error instanceof Error ? error.message : String(error),
      });
    } finally {
      setSaving(false);
    }
  }

  async function handleToggleAiEnabled(enabled: boolean) {
    setSavingEnabled(true);
    try {
      const next = await saveAiSettings({ enabled });
      setSettings(next);
      setDraft((current) => (current ? { ...current, enabled: next.enabled } : current));
      toast.success(next.enabled ? "新告警會送 AI 解析" : "新告警已停止送 AI 解析");
    } catch (error) {
      toast.error("更新 AI 解析狀態失敗", {
        description: error instanceof Error ? error.message : String(error),
      });
    } finally {
      setSavingEnabled(false);
    }
  }

  async function handleUseProvider() {
    if (!draft) return;
    setUsingProvider(true);
    try {
      const next = await activateAiProvider(draft.provider);
      setSettings(next);
      setDraft(draftFromProvider(next, draft.provider));
      toast.success(next.message || "已切換使用模型");
    } catch (error) {
      toast.error("切換失敗", {
        description: error instanceof Error ? error.message : String(error),
      });
    } finally {
      setUsingProvider(false);
    }
  }

  async function handleTest() {
    setTesting(true);
    try {
      const result = await testAiSettings();
      toast.success(result.message || "AI 模型連線測試成功", {
        description: `${result.provider} / ${result.model}`,
      });
    } catch (error) {
      toast.error("測試失敗", {
        description: error instanceof Error ? error.message : String(error),
      });
    } finally {
      setTesting(false);
    }
  }

  const fetchModelsForDraft = useCallback(async (nextDraft: Draft, showToast = false) => {
    if (!nextDraft.base_url) {
      setModelOptions([]);
      setModelHint("請先設定 Base URL。");
      return;
    }
    setLoadingModels(true);
    try {
      const result = await fetchAiModels({
        provider: nextDraft.provider,
        base_url: nextDraft.base_url,
        api_key: nextDraft.api_key || undefined,
      });
      setModelOptions(result.models);
      setModelHint(result.models.length > 0 ? "請從已讀取的模型清單選取。" : "未讀到模型清單，請確認服務已啟動。");
      if (showToast) toast.success(result.message || "模型清單已更新");
      if (!nextDraft.model && result.models[0]) {
        setDraft((current) => (current ? { ...current, model: result.models[0] } : current));
      }
    } catch (error) {
      setModelOptions([]);
      setModelHint(
        nextDraft.provider === "openai"
          ? "請先填入 API Key，系統才可讀取 OpenAI 模型清單。"
          : "讀取模型清單失敗，請確認 Base URL 與本機模型服務狀態。"
      );
      if (showToast) {
        toast.error("讀取模型清單失敗", {
          description: error instanceof Error ? error.message : String(error),
        });
      }
    } finally {
      setLoadingModels(false);
    }
  }, []);

  useEffect(() => {
    if (!draft) return;
    const snapshot = { ...draft };
    let active = true;
    const timer = window.setTimeout(() => {
      if (!active) return;
      void fetchModelsForDraft(snapshot);
    }, 500);
    return () => {
      active = false;
      window.clearTimeout(timer);
    };
  }, [draft, fetchModelsForDraft]);

  const visibleModelOptions = Array.from(new Set([...(draft?.model ? [draft.model] : []), ...modelOptions]));

  return (
    <div className="flex h-full flex-col">
      <header className="flex items-center justify-between border-b border-border bg-card px-6 py-4">
        <div className="flex items-center gap-3">
          <div className="flex size-10 items-center justify-center rounded-lg bg-primary/10">
            <BrainCircuit className="size-5 text-primary" />
          </div>
          <div>
            <h1 className="text-xl font-semibold">AI模型設定</h1>
            <p className="text-sm text-muted-foreground">
              分開儲存模型設定與切換目前使用模型，避免誤切到尚未設定的供應商。
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <ThemeToggle />
        </div>
      </header>

      <main className="flex-1 overflow-auto p-6">
        <div className="mx-auto max-w-6xl space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>目前生效模型</CardTitle>
              <CardDescription>
                新進 Wazuh 告警只會送到目前生效的模型；點選下方卡片只是切換編輯表單。
              </CardDescription>
            </CardHeader>
            <CardContent className="grid gap-4 text-sm md:grid-cols-[1fr_320px]">
              <div className="grid gap-3 sm:grid-cols-2">
                <div>
                  <div className="text-muted-foreground">供應商</div>
                  <div className="mt-1 font-medium">{activeProvider?.label_zh || settings?.provider || "-"}</div>
                </div>
                <div>
                  <div className="text-muted-foreground">模型</div>
                  <div className="mt-1 truncate font-medium">{settings?.model || "-"}</div>
                </div>
              </div>
              <div>
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="text-muted-foreground">新告警送 AI 解析</div>
                    <p className="mt-1 text-xs text-muted-foreground">
                      關閉時仍保存原始 Log，但不呼叫模型。
                    </p>
                  </div>
                  <Switch
                    checked={settings?.enabled ?? false}
                    onCheckedChange={(value) => void handleToggleAiEnabled(Boolean(value))}
                    disabled={loading || savingEnabled}
                    aria-label="新告警送 AI 解析"
                  />
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>模型設定檔</CardTitle>
              <CardDescription>
                點卡片只會切換下方表單；按「使用此模型」才會改變目前生效模型。
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                {(settings?.providers || []).map((provider) => {
                  const isEditing = draft?.provider === provider.key;
                  const isActive = settings?.active_provider === provider.key;
                  return (
                    <button
                      key={provider.key}
                      type="button"
                      className={`rounded-lg border p-4 text-left transition-colors ${
                        isEditing ? "border-primary bg-primary/10 text-primary" : "border-border hover:bg-muted"
                      }`}
                      onClick={() => selectProvider(provider.key)}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <div className="font-medium">{provider.label_zh}</div>
                        {isActive && <Badge variant="secondary">目前使用</Badge>}
                      </div>
                      <p className="mt-2 text-xs text-muted-foreground">{provider.help_zh}</p>
                    </button>
                  );
                })}
              </div>

              <div className="grid gap-4 lg:grid-cols-2">
                <div className="space-y-2">
                  <label className="text-sm font-medium">Base URL</label>
                  <Input
                    value={draft?.base_url || ""}
                    onChange={(event) => updateDraft("base_url", event.target.value)}
                    placeholder="https://api.openai.com/v1"
                  />
                  <p className="text-xs text-muted-foreground">
                    系統會自動呼叫 <code>/chat/completions</code>。
                  </p>
                </div>
                <div className="space-y-2">
                  <label className="text-sm font-medium">Model</label>
                  <select
                    className="h-8 w-full rounded-lg border border-input bg-background px-2.5 py-1 text-sm outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 disabled:cursor-not-allowed disabled:opacity-60"
                    value={draft?.model || ""}
                    onChange={(event) => updateDraft("model", event.target.value)}
                    disabled={loadingModels || visibleModelOptions.length === 0}
                  >
                    <option value="">{loadingModels ? "正在讀取模型..." : "選擇模型"}</option>
                    {visibleModelOptions.map((model) => (
                      <option key={model} value={model}>{model}</option>
                    ))}
                  </select>
                  <p className="text-xs text-muted-foreground">
                    {modelHint}
                  </p>
                </div>
                <div className="space-y-2">
                  <div className="flex items-center justify-between gap-3">
                    <label className="text-sm font-medium">API Key</label>
                    <span className="text-xs text-muted-foreground">
                      {editingProvider?.api_key_configured ? `已設定：${editingProvider.api_key_preview}` : "未設定"}
                    </span>
                  </div>
                  <div className="relative">
                    <KeyRound className="pointer-events-none absolute left-2.5 top-2 size-4 text-muted-foreground" />
                    <Input
                      className="pl-8"
                      type="password"
                      value={draft?.api_key || ""}
                      onChange={(event) => updateDraft("api_key", event.target.value)}
                      placeholder={editingProvider?.api_key_configured ? `${editingProvider.api_key_preview}，留空代表不變` : "OpenAI 或相容服務 API key"}
                    />
                  </div>
                  {editingProvider?.api_key_configured && (
                    <label className="flex items-center gap-2 text-sm text-muted-foreground">
                      <input
                        type="checkbox"
                        checked={draft?.clear_api_key || false}
                        onChange={(event) => updateDraft("clear_api_key", event.target.checked)}
                      />
                      清除此模型設定檔的 API Key
                    </label>
                  )}
                </div>
                <div className="grid gap-4 sm:grid-cols-2">
                  <div className="space-y-2">
                    <label className="text-sm font-medium">Timeout 秒數</label>
                    <Input
                      type="number"
                      min={5}
                      max={300}
                      value={draft?.timeout_s ?? 60}
                      onChange={(event) => updateDraft("timeout_s", Number(event.target.value))}
                    />
                  </div>
                  <div className="space-y-2">
                    <label className="text-sm font-medium">並行上限</label>
                    <Input
                      type="number"
                      min={1}
                      max={16}
                      value={draft?.max_concurrent_requests ?? 2}
                      onChange={(event) => updateDraft("max_concurrent_requests", Number(event.target.value))}
                    />
                  </div>
                </div>
              </div>

              <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <div className="flex flex-wrap items-center gap-2">
                  <label className="flex items-center gap-2 rounded-lg border bg-background px-3 py-2 text-sm">
                    <Switch
                      checked={draft?.provider === settings?.active_provider}
                      onCheckedChange={(value) => {
                        if (value && draft?.provider !== settings?.active_provider) {
                          void handleUseProvider();
                        }
                      }}
                      disabled={!draft || usingProvider || loading || hasUnsavedProviderChanges}
                      aria-label="使用此模型"
                    />
                    {usingProvider
                      ? "切換中..."
                      : draft?.provider === settings?.active_provider
                        ? "目前使用此模型"
                        : "使用此模型"}
                  </label>
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => void handleTest()}
                    disabled={testing || saving || savingEnabled || !settings?.enabled}
                  >
                    <TestTube data-icon="inline-start" />
                    {testing ? "測試中..." : "測試目前使用模型"}
                  </Button>
                </div>
                <Button type="button" onClick={() => void handleSave()} disabled={!draft || saving || loading}>
                  <Save data-icon="inline-start" />
                  {saving ? "儲存中..." : "儲存此模型設定"}
                </Button>
              </div>
              {hasUnsavedProviderChanges && (
                <p className="text-sm text-muted-foreground">
                  這個模型設定檔有尚未儲存的變更；請先儲存，再切換使用。
                </p>
              )}
            </CardContent>
          </Card>
        </div>
      </main>
    </div>
  );
}

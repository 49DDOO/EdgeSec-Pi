"use client";

import { useEffect, useMemo, useState } from "react";
import { Bell, Mail, MessageCircle, RefreshCw, Save, Send, TestTube } from "lucide-react";
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
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  fetchNotificationSettings,
  saveNotificationSettings,
  testNotificationChannel,
  type NotificationChannelStatus,
  type NotificationSettingsResponse,
} from "@/lib/api";

type ChannelKey = NotificationChannelStatus["channel"];
type Drafts = Record<ChannelKey, Record<string, string | boolean>>;

const channels: Array<{
  key: ChannelKey;
  label: string;
  icon: typeof MessageCircle;
  description: string;
  help: string;
}> = [
  {
    key: "line",
    label: "LINE",
    icon: MessageCircle,
    description: "適合不熟 Slack 的管理者，測試成功後才算完成。",
    help: "需要 LINE Channel Access Token，以及接收訊息的 User ID 或群組 ID。已設定的權杖不會顯示；留空代表沿用原本設定。",
  },
  {
    key: "slack",
    label: "Slack",
    icon: MessageCircle,
    description: "適合有 IT 或外包團隊的公司，可搭配互動按鈕。",
    help: "只要通知可先填 Webhook URL。若要 Slack 按鈕回應，還需要 Bot Token、App Token、Channel ID 與公開連結。",
  },
  {
    key: "telegram",
    label: "Telegram",
    icon: Send,
    description: "適合偏好 Telegram Bot 的團隊。",
    help: "需要 Bot Token 與 Chat ID。已設定的 Bot Token 不會顯示；留空代表沿用原本設定。",
  },
  {
    key: "email",
    label: "Email",
    icon: Mail,
    description: "適合作為備援通知管道。",
    help: "需要 SMTP 主機、寄件者與收件者。若 SMTP 需要密碼，已設定時可留空沿用。",
  },
];

const fieldOrder: Record<ChannelKey, string[]> = {
  line: ["LINE_CHANNEL_ACCESS_TOKEN", "LINE_USER_ID"],
  slack: [
    "SLACK_WEBHOOK_URL",
    "SLACK_CHANNEL_ID",
    "SLACK_BOT_TOKEN",
    "SLACK_APP_TOKEN",
    "BRIDGE_PUBLIC_URL",
  ],
  telegram: ["TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID"],
  email: ["SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASS", "EMAIL_FROM", "EMAIL_TO"],
};

function blankDrafts(): Drafts {
  return { line: {}, slack: {}, telegram: {}, email: {} };
}

function draftsFromSettings(settings: NotificationSettingsResponse): Drafts {
  const next = blankDrafts();
  for (const channel of channels) {
    const fields = settings.channels[channel.key]?.fields || {};
    for (const [key, field] of Object.entries(fields)) {
      if (field.secret) {
        next[channel.key][key] = "";
      } else {
        next[channel.key][key] = field.value ?? "";
      }
    }
  }
  return next;
}

function StatusBadge({ status }: { status?: NotificationChannelStatus }) {
  if (!status?.configured) {
    return <Badge variant="outline">尚未設定</Badge>;
  }
  if (status.lastTested) {
    return <Badge className="bg-emerald-600 text-white hover:bg-emerald-600">測試成功</Badge>;
  }
  return <Badge variant="secondary">已設定，待測試</Badge>;
}

function FieldInput({
  fieldKey,
  settings,
  value,
  onChange,
}: {
  fieldKey: string;
  settings?: NotificationChannelStatus;
  value: string | boolean;
  onChange: (key: string, value: string | boolean) => void;
}) {
  const field = settings?.fields[fieldKey];
  if (!field) return null;
  const label = field.label || fieldKey;
  const placeholder = field.secret && field.configured ? "已設定，留空代表不變" : "";
  const type = field.secret ? "password" : fieldKey.includes("EMAIL") ? "email" : "text";

  if (fieldKey === "SMTP_SSL" || fieldKey === "SMTP_STARTTLS") {
    return (
      <label className="flex items-center gap-2 rounded-lg border border-border px-3 py-2 text-sm">
        <input
          type="checkbox"
          checked={Boolean(value)}
          onChange={(event) => onChange(fieldKey, event.target.checked)}
        />
        {label}
      </label>
    );
  }

  return (
    <div className="space-y-2">
      <label className="text-sm font-medium">{label}</label>
      <Input
        type={type}
        value={String(value ?? "")}
        onChange={(event) => onChange(fieldKey, event.target.value)}
        placeholder={placeholder}
      />
    </div>
  );
}

export default function NotificationsPage() {
  const [settings, setSettings] = useState<NotificationSettingsResponse | null>(null);
  const [drafts, setDrafts] = useState<Drafts>(blankDrafts);
  const [active, setActive] = useState<ChannelKey>("line");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState<ChannelKey | null>(null);
  const [testing, setTesting] = useState<ChannelKey | null>(null);

  const activeStatus = settings?.channels[active];
  const configuredCount = useMemo(
    () => channels.filter((channel) => settings?.channels[channel.key]?.configured).length,
    [settings]
  );
  const testedCount = useMemo(
    () => channels.filter((channel) => settings?.channels[channel.key]?.lastTested).length,
    [settings]
  );

  async function loadSettings() {
    setLoading(true);
    try {
      const next = await fetchNotificationSettings();
      setSettings(next);
      setDrafts(draftsFromSettings(next));
    } catch (error) {
      toast.error("讀取通知設定失敗", {
        description: error instanceof Error ? error.message : String(error),
      });
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    fetchNotificationSettings()
      .then((next) => {
        setSettings(next);
        setDrafts(draftsFromSettings(next));
      })
      .catch((error) => {
        toast.error("讀取通知設定失敗", {
          description: error instanceof Error ? error.message : String(error),
        });
      })
      .finally(() => setLoading(false));
  }, []);

  function updateDraft(channel: ChannelKey, key: string, value: string | boolean) {
    setDrafts((previous) => ({
      ...previous,
      [channel]: { ...previous[channel], [key]: value },
    }));
  }

  async function handleSave(channel: ChannelKey) {
    setSaving(channel);
    try {
      const next = await saveNotificationSettings(channel, drafts[channel]);
      setSettings(next);
      setDrafts(draftsFromSettings(next));
      toast.success(next.message || "設定已儲存");
    } catch (error) {
      toast.error("儲存失敗", {
        description: error instanceof Error ? error.message : String(error),
      });
    } finally {
      setSaving(null);
    }
  }

  async function handleTest(channel: ChannelKey) {
    setTesting(channel);
    try {
      const next = await testNotificationChannel(channel);
      setSettings(next);
      setDrafts(draftsFromSettings(next));
      toast.success(next.message || "測試訊息已送出");
    } catch (error) {
      toast.error("測試失敗", {
        description: error instanceof Error ? error.message : String(error),
      });
    } finally {
      setTesting(null);
    }
  }

  return (
    <div className="flex h-full flex-col">
      <header className="flex items-center justify-between border-b border-border bg-card px-6 py-4">
        <div className="flex items-center gap-3">
          <div className="flex size-10 items-center justify-center rounded-lg bg-primary/10">
            <Bell className="size-5 text-primary" />
          </div>
          <div>
            <h1 className="text-xl font-semibold">通知設定</h1>
            <p className="text-sm text-muted-foreground">
              先測通至少一個通知管道，再開始等告警
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" onClick={loadSettings} disabled={loading}>
            <RefreshCw data-icon="inline-start" />
            重新整理
          </Button>
          <ThemeToggle />
        </div>
      </header>

      <main className="flex-1 overflow-auto p-6">
        <div className="mx-auto max-w-6xl space-y-6">
          <div className="grid gap-4 md:grid-cols-[1fr_280px]">
            <Card>
              <CardHeader>
                <CardTitle>上線前先確認通知會到</CardTitle>
                <CardDescription>
                  LINE、Slack、Telegram、Email 可分開設定。每個管道儲存後都要按一次測試。
                </CardDescription>
              </CardHeader>
            </Card>
            <Card>
              <CardContent className="space-y-3 p-4 text-sm">
                <div className="flex items-center justify-between">
                  <span className="text-muted-foreground">已設定</span>
                  <strong>{configuredCount}/4</strong>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-muted-foreground">測試成功</span>
                  <strong>{testedCount}/4</strong>
                </div>
              </CardContent>
            </Card>
          </div>

          <Tabs value={active} onValueChange={(value) => setActive(value as ChannelKey)} className="space-y-4">
            <TabsList className="grid w-full grid-cols-4">
              {channels.map(({ key, label, icon: Icon }) => (
                <TabsTrigger key={key} value={key} className="gap-2">
                  <Icon className="size-4" />
                  {label}
                </TabsTrigger>
              ))}
            </TabsList>

            {channels.map(({ key, label, icon: Icon, description, help }) => {
              const status = settings?.channels[key];
              const values = drafts[key] || {};
              const orderedFields = key === "email"
                ? [...fieldOrder.email, "SMTP_SSL", "SMTP_STARTTLS"]
                : fieldOrder[key];

              return (
                <TabsContent key={key} value={key}>
                  <Card>
                    <CardHeader>
                      <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
                        <div className="space-y-2">
                          <CardTitle className="flex items-center gap-2">
                            <Icon className="size-5" />
                            {label}
                          </CardTitle>
                          <CardDescription>{description}</CardDescription>
                        </div>
                        <StatusBadge status={status} />
                      </div>
                    </CardHeader>
                    <CardContent className="space-y-6">
                      <details className="rounded-lg border border-border bg-muted/30 px-4 py-3">
                        <summary className="cursor-pointer text-sm font-medium">設定說明</summary>
                        <p className="mt-2 text-sm text-muted-foreground">{help}</p>
                      </details>

                      <div className="grid gap-6 lg:grid-cols-[1fr_280px]">
                        <div className="grid gap-4 sm:grid-cols-2">
                          {orderedFields.map((fieldKey) => (
                            <FieldInput
                              key={fieldKey}
                              fieldKey={fieldKey}
                              settings={status}
                              value={values[fieldKey] ?? ""}
                              onChange={(field, value) => updateDraft(key, field, value)}
                            />
                          ))}
                        </div>

                        <div className="rounded-lg border border-border p-4">
                          <h3 className="text-sm font-semibold">目前狀態</h3>
                          <div className="mt-4 space-y-3 text-sm">
                            <div className="flex items-center justify-between gap-4">
                              <span className="text-muted-foreground">設定</span>
                              <span className="font-medium">{status?.configured ? "已設定" : "尚未設定"}</span>
                            </div>
                            <div className="flex items-center justify-between gap-4">
                              <span className="text-muted-foreground">最後測試</span>
                              <span className="text-right font-medium">{status?.lastTested || "尚未測試成功"}</span>
                            </div>
                          </div>
                        </div>
                      </div>

                      <div className="flex flex-wrap gap-2">
                        <Button onClick={() => handleSave(key)} disabled={saving === key || loading}>
                          <Save data-icon="inline-start" />
                          {saving === key ? "儲存中..." : `儲存 ${label}`}
                        </Button>
                        <Button
                          variant="outline"
                          onClick={() => handleTest(key)}
                          disabled={testing === key || !status?.configured}
                        >
                          <TestTube data-icon="inline-start" />
                          {testing === key ? "測試中..." : `測試 ${label}`}
                        </Button>
                      </div>
                    </CardContent>
                  </Card>
                </TabsContent>
              );
            })}
          </Tabs>

          {activeStatus && !activeStatus.configured && (
            <p className="text-sm text-muted-foreground">
              先儲存必要欄位，測試按鈕才會開啟。這樣可以避免按了測試卻不知道哪裡少填。
            </p>
          )}
        </div>
      </main>
    </div>
  );
}

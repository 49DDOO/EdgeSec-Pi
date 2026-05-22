"use client";

import { useState } from "react";
import {
  Bell,
  MessageCircle,
  Mail,
  Send,
  Check,
  X,
  TestTube,
  Info,
  ExternalLink,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ThemeToggle } from "@/components/dashboard/theme-toggle";
import { toast } from "sonner";

interface ChannelConfig {
  enabled: boolean;
  configured: boolean;
  lastTested: string | null;
}

interface NotificationChannels {
  line: ChannelConfig & { token: string };
  slack: ChannelConfig & { webhookUrl: string };
  telegram: ChannelConfig & { botToken: string; chatId: string };
  email: ChannelConfig & { smtpHost: string; from: string; to: string };
}

const initialChannels: NotificationChannels = {
  line: {
    enabled: true,
    configured: true,
    lastTested: "2024-01-15 14:30",
    token: "••••••••••••••••••••",
  },
  slack: {
    enabled: false,
    configured: false,
    lastTested: null,
    webhookUrl: "",
  },
  telegram: {
    enabled: false,
    configured: false,
    lastTested: null,
    botToken: "",
    chatId: "",
  },
  email: {
    enabled: false,
    configured: true,
    lastTested: "2024-01-10 09:15",
    smtpHost: "smtp.gmail.com",
    from: "alert@company.com",
    to: "admin@company.com",
  },
};

function StatusBadge({ configured, lastTested }: { configured: boolean; lastTested: string | null }) {
  if (!configured) {
    return <Badge variant="outline" className="text-muted-foreground">尚未設定</Badge>;
  }
  if (lastTested) {
    return <Badge className="bg-green-500 text-white">已測試成功</Badge>;
  }
  return <Badge variant="secondary">已設定，待測試</Badge>;
}

export default function NotificationsPage() {
  const [channels, setChannels] = useState<NotificationChannels>(initialChannels);
  const [testing, setTesting] = useState<string | null>(null);

  const handleToggle = (channel: keyof NotificationChannels) => {
    if (!channels[channel].configured) {
      toast.error("請先完成設定", { description: "需要先填寫並儲存設定才能啟用" });
      return;
    }
    setChannels((prev) => ({
      ...prev,
      [channel]: { ...prev[channel], enabled: !prev[channel].enabled },
    }));
    toast.success(channels[channel].enabled ? "已停用通知" : "已啟用通知");
  };

  const handleTest = async (channel: string) => {
    setTesting(channel);
    // Simulate API call
    await new Promise((resolve) => setTimeout(resolve, 2000));
    setTesting(null);
    toast.success("測試訊息已發送", {
      description: "請檢查您的通知管道是否收到測試訊息",
    });
  };

  const handleSave = (channel: string) => {
    toast.success("設定已儲存", {
      description: `${channel} 通知設定已更新`,
    });
  };

  return (
    <div className="flex h-full flex-col">
      {/* Page Header */}
      <header className="flex items-center justify-between border-b border-border bg-card px-6 py-4">
        <div className="flex items-center gap-3">
          <div className="flex size-10 items-center justify-center rounded-lg bg-primary/10">
            <Bell className="size-5 text-primary" />
          </div>
          <div>
            <h1 className="text-xl font-semibold">通知設定</h1>
            <p className="text-sm text-muted-foreground">
              設定如何接收資安告警通知
            </p>
          </div>
        </div>
        <ThemeToggle />
      </header>

      {/* Main Content */}
      <main className="flex-1 overflow-auto p-6">
        <div className="mx-auto max-w-4xl space-y-6">
          {/* Info Banner */}
          <Card className="border-blue-200 bg-blue-50 dark:border-blue-900 dark:bg-blue-950/30">
            <CardContent className="flex items-start gap-3 pt-4">
              <Info className="mt-0.5 size-5 shrink-0 text-blue-600 dark:text-blue-400" />
              <div className="text-sm text-blue-800 dark:text-blue-200">
                <p className="font-medium">選擇您方便收到通知的管道</p>
                <p className="mt-1 text-blue-700 dark:text-blue-300">
                  當系統偵測到重要資安事件時，會透過已啟用的管道通知您。
                  建議至少啟用一個通知管道，以免錯過重要告警。
                </p>
              </div>
            </CardContent>
          </Card>

          {/* Quick Overview */}
          <div className="grid gap-4 sm:grid-cols-4">
            {[
              { key: "line" as const, name: "LINE", icon: MessageCircle, color: "bg-green-500" },
              { key: "slack" as const, name: "Slack", icon: MessageCircle, color: "bg-purple-500" },
              { key: "telegram" as const, name: "Telegram", icon: Send, color: "bg-blue-500" },
              { key: "email" as const, name: "Email", icon: Mail, color: "bg-orange-500" },
            ].map(({ key, name, icon: Icon, color }) => (
              <Card
                key={key}
                className={channels[key].enabled ? "border-primary" : ""}
              >
                <CardContent className="flex items-center justify-between p-4">
                  <div className="flex items-center gap-3">
                    <div className={`flex size-9 items-center justify-center rounded-lg ${color}`}>
                      <Icon className="size-4 text-white" />
                    </div>
                    <div>
                      <p className="text-sm font-medium">{name}</p>
                      <p className="text-xs text-muted-foreground">
                        {channels[key].enabled ? "已啟用" : "未啟用"}
                      </p>
                    </div>
                  </div>
                  {channels[key].configured ? (
                    channels[key].enabled ? (
                      <Check className="size-5 text-green-500" />
                    ) : (
                      <X className="size-5 text-muted-foreground" />
                    )
                  ) : (
                    <span className="text-xs text-muted-foreground">待設定</span>
                  )}
                </CardContent>
              </Card>
            ))}
          </div>

          {/* Detailed Settings */}
          <Tabs defaultValue="line" className="space-y-4">
            <TabsList className="grid w-full grid-cols-4">
              <TabsTrigger value="line" className="gap-2">
                <MessageCircle className="size-4" />
                LINE
              </TabsTrigger>
              <TabsTrigger value="slack" className="gap-2">
                <MessageCircle className="size-4" />
                Slack
              </TabsTrigger>
              <TabsTrigger value="telegram" className="gap-2">
                <Send className="size-4" />
                Telegram
              </TabsTrigger>
              <TabsTrigger value="email" className="gap-2">
                <Mail className="size-4" />
                Email
              </TabsTrigger>
            </TabsList>

            {/* LINE */}
            <TabsContent value="line">
              <Card>
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <div>
                      <CardTitle className="flex items-center gap-2">
                        LINE Notify
                        <StatusBadge
                          configured={channels.line.configured}
                          lastTested={channels.line.lastTested}
                        />
                      </CardTitle>
                      <CardDescription>
                        透過 LINE Notify 接收告警通知到您的 LINE 群組
                      </CardDescription>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-sm text-muted-foreground">啟用</span>
                      <Switch
                        checked={channels.line.enabled}
                        onCheckedChange={() => handleToggle("line")}
                      />
                    </div>
                  </div>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="space-y-2">
                    <label className="text-sm font-medium">LINE Notify Token</label>
                    <Input
                      type="password"
                      value={channels.line.token}
                      onChange={(e) =>
                        setChannels((prev) => ({
                          ...prev,
                          line: { ...prev.line, token: e.target.value },
                        }))
                      }
                      placeholder="輸入您的 LINE Notify Token"
                    />
                    <p className="text-xs text-muted-foreground">
                      到{" "}
                      <a
                        href="https://notify-bot.line.me/"
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-primary hover:underline"
                      >
                        LINE Notify 官網
                        <ExternalLink className="ml-1 inline size-3" />
                      </a>
                      {" "}申請 Token
                    </p>
                  </div>
                  {channels.line.lastTested && (
                    <p className="text-sm text-muted-foreground">
                      上次測試成功：{channels.line.lastTested}
                    </p>
                  )}
                  <div className="flex gap-2">
                    <Button onClick={() => handleSave("LINE")}>儲存設定</Button>
                    <Button
                      variant="outline"
                      onClick={() => handleTest("line")}
                      disabled={testing === "line"}
                    >
                      <TestTube data-icon="inline-start" />
                      {testing === "line" ? "發送中..." : "發送測試訊息"}
                    </Button>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>

            {/* Slack */}
            <TabsContent value="slack">
              <Card>
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <div>
                      <CardTitle className="flex items-center gap-2">
                        Slack Webhook
                        <StatusBadge
                          configured={channels.slack.configured}
                          lastTested={channels.slack.lastTested}
                        />
                      </CardTitle>
                      <CardDescription>
                        透過 Slack Incoming Webhook 發送告警到指定頻道
                      </CardDescription>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-sm text-muted-foreground">啟用</span>
                      <Switch
                        checked={channels.slack.enabled}
                        onCheckedChange={() => handleToggle("slack")}
                      />
                    </div>
                  </div>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="space-y-2">
                    <label className="text-sm font-medium">Webhook URL</label>
                    <Input
                      type="password"
                      value={channels.slack.webhookUrl}
                      onChange={(e) =>
                        setChannels((prev) => ({
                          ...prev,
                          slack: { ...prev.slack, webhookUrl: e.target.value },
                        }))
                      }
                      placeholder="https://hooks.slack.com/services/..."
                    />
                    <p className="text-xs text-muted-foreground">
                      在 Slack App 設定中建立 Incoming Webhook
                    </p>
                  </div>
                  <div className="flex gap-2">
                    <Button onClick={() => handleSave("Slack")}>儲存設定</Button>
                    <Button
                      variant="outline"
                      onClick={() => handleTest("slack")}
                      disabled={testing === "slack" || !channels.slack.webhookUrl}
                    >
                      <TestTube data-icon="inline-start" />
                      {testing === "slack" ? "發送中..." : "發送測試訊息"}
                    </Button>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>

            {/* Telegram */}
            <TabsContent value="telegram">
              <Card>
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <div>
                      <CardTitle className="flex items-center gap-2">
                        Telegram Bot
                        <StatusBadge
                          configured={channels.telegram.configured}
                          lastTested={channels.telegram.lastTested}
                        />
                      </CardTitle>
                      <CardDescription>
                        透過 Telegram Bot 發送告警到指定聊天室
                      </CardDescription>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-sm text-muted-foreground">啟用</span>
                      <Switch
                        checked={channels.telegram.enabled}
                        onCheckedChange={() => handleToggle("telegram")}
                      />
                    </div>
                  </div>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid gap-4 sm:grid-cols-2">
                    <div className="space-y-2">
                      <label className="text-sm font-medium">Bot Token</label>
                      <Input
                        type="password"
                        value={channels.telegram.botToken}
                        onChange={(e) =>
                          setChannels((prev) => ({
                            ...prev,
                            telegram: { ...prev.telegram, botToken: e.target.value },
                          }))
                        }
                        placeholder="123456789:ABC..."
                      />
                    </div>
                    <div className="space-y-2">
                      <label className="text-sm font-medium">Chat ID</label>
                      <Input
                        value={channels.telegram.chatId}
                        onChange={(e) =>
                          setChannels((prev) => ({
                            ...prev,
                            telegram: { ...prev.telegram, chatId: e.target.value },
                          }))
                        }
                        placeholder="-1001234567890"
                      />
                    </div>
                  </div>
                  <p className="text-xs text-muted-foreground">
                    透過 @BotFather 建立 Bot 並取得 Token，Chat ID 可從 @userinfobot 取得
                  </p>
                  <div className="flex gap-2">
                    <Button onClick={() => handleSave("Telegram")}>儲存設定</Button>
                    <Button
                      variant="outline"
                      onClick={() => handleTest("telegram")}
                      disabled={testing === "telegram" || !channels.telegram.botToken}
                    >
                      <TestTube data-icon="inline-start" />
                      {testing === "telegram" ? "發送中..." : "發送測試訊息"}
                    </Button>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>

            {/* Email */}
            <TabsContent value="email">
              <Card>
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <div>
                      <CardTitle className="flex items-center gap-2">
                        Email 通知
                        <StatusBadge
                          configured={channels.email.configured}
                          lastTested={channels.email.lastTested}
                        />
                      </CardTitle>
                      <CardDescription>
                        透過 Email 發送告警通知
                      </CardDescription>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-sm text-muted-foreground">啟用</span>
                      <Switch
                        checked={channels.email.enabled}
                        onCheckedChange={() => handleToggle("email")}
                      />
                    </div>
                  </div>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid gap-4 sm:grid-cols-3">
                    <div className="space-y-2">
                      <label className="text-sm font-medium">SMTP 主機</label>
                      <Input
                        value={channels.email.smtpHost}
                        onChange={(e) =>
                          setChannels((prev) => ({
                            ...prev,
                            email: { ...prev.email, smtpHost: e.target.value },
                          }))
                        }
                        placeholder="smtp.gmail.com"
                      />
                    </div>
                    <div className="space-y-2">
                      <label className="text-sm font-medium">寄件者</label>
                      <Input
                        type="email"
                        value={channels.email.from}
                        onChange={(e) =>
                          setChannels((prev) => ({
                            ...prev,
                            email: { ...prev.email, from: e.target.value },
                          }))
                        }
                        placeholder="alert@company.com"
                      />
                    </div>
                    <div className="space-y-2">
                      <label className="text-sm font-medium">收件者</label>
                      <Input
                        type="email"
                        value={channels.email.to}
                        onChange={(e) =>
                          setChannels((prev) => ({
                            ...prev,
                            email: { ...prev.email, to: e.target.value },
                          }))
                        }
                        placeholder="admin@company.com"
                      />
                    </div>
                  </div>
                  {channels.email.lastTested && (
                    <p className="text-sm text-muted-foreground">
                      上次測試成功：{channels.email.lastTested}
                    </p>
                  )}
                  <div className="flex gap-2">
                    <Button onClick={() => handleSave("Email")}>儲存設定</Button>
                    <Button
                      variant="outline"
                      onClick={() => handleTest("email")}
                      disabled={testing === "email" || !channels.email.smtpHost}
                    >
                      <TestTube data-icon="inline-start" />
                      {testing === "email" ? "發送中..." : "發送測試訊息"}
                    </Button>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>
        </div>
      </main>
    </div>
  );
}

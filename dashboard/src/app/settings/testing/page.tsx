"use client";

import { ShieldCheck, TestTube2 } from "lucide-react";
import { SampleDataTester } from "@/components/dashboard/sample-data-tester";
import { PageHeader } from "@/components/dashboard/page-header";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

export default function TestingPage() {
  return (
    <div className="flex h-full flex-col">
      <PageHeader
        icon={TestTube2}
        title="流程測試"
        description="確認資料來源、LLM、Dashboard 與通知流程是否正常"
      />

      <main className="flex-1 overflow-auto p-6">
        <div className="mx-auto max-w-5xl space-y-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <ShieldCheck className="size-5" />
                這裡只放測試操作
              </CardTitle>
              <CardDescription>
                測試資料會清楚標示，不會混入正式健康分數。正式事件仍在戰情中心處理。
              </CardDescription>
            </CardHeader>
            <CardContent className="grid gap-4 text-sm text-muted-foreground md:grid-cols-3">
              <div className="rounded-lg border border-border p-4">
                <div className="font-medium text-foreground">1. 加入 Wazuh Sample Data</div>
                <p className="mt-2">先在 Wazuh Dashboard 加入 Sample security information。</p>
              </div>
              <div className="rounded-lg border border-border p-4">
                <div className="font-medium text-foreground">2. 送出測試事件</div>
                <p className="mt-2">按下方按鈕，系統會挑 1 筆測試資料跑完整流程。</p>
              </div>
              <div className="rounded-lg border border-border p-4">
                <div className="font-medium text-foreground">3. 確認有收到通知</div>
                <p className="mt-2">LINE、Slack、Telegram 或 Email 會標示這是測試資料。</p>
              </div>
            </CardContent>
          </Card>

          <SampleDataTester />
        </div>
      </main>
    </div>
  );
}

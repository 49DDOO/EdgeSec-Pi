"use client";

import { useEffect, useState } from "react";
import { Database, Loader2, Send, TestTube2 } from "lucide-react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  fetchSampleDataStatus,
  replayBuiltInTestAlert,
  replaySampleData,
  type SampleDataStatus,
} from "@/lib/api";

export function SampleDataTester() {
  const [status, setStatus] = useState<SampleDataStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [sendingBuiltIn, setSendingBuiltIn] = useState(false);
  const [sendingWazuh, setSendingWazuh] = useState(false);

  async function loadStatus() {
    setLoading(true);
    try {
      setStatus(await fetchSampleDataStatus("security"));
    } catch (error) {
      setStatus(null);
      toast.error("無法讀取 Wazuh 測試資料", {
        description: error instanceof Error ? error.message : String(error),
      });
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    let active = true;
    fetchSampleDataStatus("security")
      .then((next) => {
        if (active) setStatus(next);
      })
      .catch((error) => {
        if (!active) return;
        setStatus(null);
        toast.error("無法讀取 Wazuh 測試資料", {
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

  async function handleBuiltInReplay() {
    setSendingBuiltIn(true);
    try {
      const result = await replayBuiltInTestAlert();
      toast.success("內建測試事件已送出", {
        description: result.message || "請確認通知管道是否收到測試訊息",
      });
    } catch (error) {
      toast.error("送出內建測試事件失敗", {
        description: error instanceof Error ? error.message : String(error),
      });
    } finally {
      setSendingBuiltIn(false);
    }
  }

  async function handleWazuhReplay() {
    setSendingWazuh(true);
    try {
      const result = await replaySampleData({ category: "security", limit: 1, min_level: 7 });
      toast.success("Wazuh 測試事件已送出", {
        description: result.message || `已送出 ${result.queued} 筆測試事件`,
      });
    } catch (error) {
      toast.error("送出 Wazuh 測試事件失敗", {
        description: error instanceof Error ? error.message : String(error),
      });
    } finally {
      setSendingWazuh(false);
    }
  }

  const available = Boolean(status?.available);
  const busy = loading || sendingBuiltIn || sendingWazuh;

  return (
    <Card>
      <CardHeader className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="space-y-1">
          <CardTitle className="flex items-center gap-2">
            <TestTube2 className="size-5" />
            測試通知流程
          </CardTitle>
          <CardDescription>
            先用內建測試事件確認通知會到；需要更貼近 Wazuh 情境時，再送 Wazuh Sample Data。
          </CardDescription>
        </div>
        <Badge variant={available ? "secondary" : "outline"}>
          {loading ? "檢查中" : available ? "測試資料可用" : "尚未加入 Sample Data"}
        </Badge>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid gap-4 lg:grid-cols-2">
          <div className="rounded-lg border border-border p-4">
            <div className="flex items-start gap-3">
              <Send className="mt-1 size-5 text-primary" />
              <div>
                <h3 className="font-semibold">EdgeSec-Pi 內建測試</h3>
                <p className="mt-1 text-sm text-muted-foreground">
                  不需要先去 Wazuh 加資料。會送 1 筆假事件，驗證 AI 解釋、資料庫與通知流程。
                </p>
              </div>
            </div>
            <Button className="mt-4" onClick={handleBuiltInReplay} disabled={busy}>
              {sendingBuiltIn ? (
                <Loader2 data-icon="inline-start" className="animate-spin" />
              ) : (
                <TestTube2 data-icon="inline-start" />
              )}
              {sendingBuiltIn ? "送出中..." : "發送內建測試事件"}
            </Button>
          </div>

          <div className="rounded-lg border border-border p-4">
            <div className="flex items-start gap-3">
              <Database className="mt-1 size-5 text-primary" />
              <div>
                <h3 className="font-semibold">Wazuh Sample Data</h3>
                <p className="mt-1 text-sm text-muted-foreground">
                  {available ? (
                    <>
                      已找到 <span className="font-medium text-foreground">{status?.sampledata_total}</span>{" "}
                      筆 Wazuh 測試資料。可送 1 筆進正式流程。
                    </>
                  ) : (
                    <>
                      尚未找到 Wazuh Sample Data。若要測 Wazuh 範例資料，請先在 Wazuh Dashboard 加入
                      Sample security information。
                    </>
                  )}
                </p>
              </div>
            </div>
            <div className="mt-4 flex flex-wrap gap-2">
              <Button variant="outline" onClick={loadStatus} disabled={busy}>
                {loading && <Loader2 data-icon="inline-start" className="animate-spin" />}
                檢查 Wazuh 測試資料
              </Button>
              <Button variant="outline" onClick={handleWazuhReplay} disabled={!available || busy}>
                {sendingWazuh ? (
                  <Loader2 data-icon="inline-start" className="animate-spin" />
                ) : (
                  <TestTube2 data-icon="inline-start" />
                )}
                {sendingWazuh ? "送出中..." : "發送 Wazuh 測試事件"}
              </Button>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

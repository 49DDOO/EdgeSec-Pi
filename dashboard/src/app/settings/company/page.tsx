"use client";

import { useState } from "react";
import { Building2, Save, Info, Plus, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ThemeToggle } from "@/components/dashboard/theme-toggle";
import { toast } from "sonner";

interface Asset {
  id: string;
  name: string;
  purpose: string;
  criticality: "critical" | "high" | "medium" | "low";
}

interface CompanyProfile {
  name: string;
  industry: string;
  timezone: string;
  description: string;
  assets: Asset[];
  riskNotes: string;
}

const initialProfile: CompanyProfile = {
  name: "範例科技有限公司",
  industry: "電子商務",
  timezone: "Asia/Taipei",
  description: "經營線上購物平台，處理信用卡付款資料。辦公時間為週一到五 9:00-18:00。",
  assets: [
    { id: "1", name: "web-server-*", purpose: "公司官網與購物網站", criticality: "critical" },
    { id: "2", name: "db-finance-*", purpose: "財務與交易資料庫", criticality: "critical" },
    { id: "3", name: "file-server-*", purpose: "內部檔案伺服器", criticality: "high" },
    { id: "4", name: "dev-*", purpose: "開發測試環境", criticality: "low" },
  ],
  riskNotes: "信用卡資料只應存在於 db-finance 伺服器\n非上班時間的管理者登入需特別注意",
};

const criticalityLabels = {
  critical: { label: "極重要", color: "bg-destructive text-destructive-foreground" },
  high: { label: "重要", color: "bg-orange-500 text-white" },
  medium: { label: "一般", color: "bg-yellow-500 text-black" },
  low: { label: "次要", color: "bg-muted text-muted-foreground" },
};

export default function CompanySettingsPage() {
  const [profile, setProfile] = useState<CompanyProfile>(initialProfile);
  const [newAsset, setNewAsset] = useState<Omit<Asset, "id">>({
    name: "",
    purpose: "",
    criticality: "medium",
  });

  const handleSave = () => {
    toast.success("設定已儲存", {
      description: "公司資料已更新，下一次告警分析時將套用新設定。",
    });
  };

  const handleAddAsset = () => {
    if (!newAsset.name || !newAsset.purpose) {
      toast.error("請填寫完整", { description: "設備名稱和用途說明都需要填寫" });
      return;
    }
    setProfile((prev) => ({
      ...prev,
      assets: [
        ...prev.assets,
        { ...newAsset, id: Date.now().toString() },
      ],
    }));
    setNewAsset({ name: "", purpose: "", criticality: "medium" });
    toast.success("已新增設備");
  };

  const handleRemoveAsset = (id: string) => {
    setProfile((prev) => ({
      ...prev,
      assets: prev.assets.filter((a) => a.id !== id),
    }));
    toast.success("已移除設備");
  };

  return (
    <div className="flex h-full flex-col">
      {/* Page Header */}
      <header className="flex items-center justify-between border-b border-border bg-card px-6 py-4">
        <div className="flex items-center gap-3">
          <div className="flex size-10 items-center justify-center rounded-lg bg-primary/10">
            <Building2 className="size-5 text-primary" />
          </div>
          <div>
            <h1 className="text-xl font-semibold">公司設定</h1>
            <p className="text-sm text-muted-foreground">
              設定公司基本資料，讓系統更了解您的業務
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Button onClick={handleSave}>
            <Save data-icon="inline-start" />
            儲存設定
          </Button>
          <ThemeToggle />
        </div>
      </header>

      {/* Main Content */}
      <main className="flex-1 overflow-auto p-6">
        <div className="mx-auto max-w-4xl space-y-6">
          {/* Info Banner */}
          <Card className="border-blue-200 bg-blue-50 dark:border-blue-900 dark:bg-blue-950/30">
            <CardContent className="flex items-start gap-3 pt-4">
              <Info className="mt-0.5 size-5 shrink-0 text-blue-600 dark:text-blue-400" />
              <div className="text-sm text-blue-800 dark:text-blue-200">
                <p className="font-medium">這些設定會讓 AI 更了解您的公司</p>
                <p className="mt-1 text-blue-700 dark:text-blue-300">
                  當系統偵測到告警時，會根據這裡的設定來判斷嚴重程度，並用您能理解的方式說明影響。
                  例如：如果「財務資料庫」被設為極重要，相關告警會被優先處理。
                </p>
              </div>
            </CardContent>
          </Card>

          {/* Company Basic Info */}
          <Card>
            <CardHeader>
              <CardTitle>公司基本資料</CardTitle>
              <CardDescription>
                讓系統知道您公司的基本情況
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid gap-4 sm:grid-cols-2">
                <div className="space-y-2">
                  <label className="text-sm font-medium">公司名稱</label>
                  <Input
                    value={profile.name}
                    onChange={(e) =>
                      setProfile((prev) => ({ ...prev, name: e.target.value }))
                    }
                    placeholder="例：美味披薩有限公司"
                  />
                </div>
                <div className="space-y-2">
                  <label className="text-sm font-medium">產業類別</label>
                  <Input
                    value={profile.industry}
                    onChange={(e) =>
                      setProfile((prev) => ({ ...prev, industry: e.target.value }))
                    }
                    placeholder="例：餐飲連鎖、電子商務、製造業"
                  />
                </div>
              </div>

              <div className="space-y-2">
                <label className="text-sm font-medium">公司簡介</label>
                <Textarea
                  value={profile.description}
                  onChange={(e) =>
                    setProfile((prev) => ({ ...prev, description: e.target.value }))
                  }
                  placeholder="簡單描述公司業務，例如：30 家門市的披薩連鎖，總部在台北。處理信用卡資料，週一到五 9-18 營業。"
                  rows={3}
                />
                <p className="text-xs text-muted-foreground">
                  2-3 句話即可，系統會根據這些資訊判斷告警的業務影響
                </p>
              </div>
            </CardContent>
          </Card>

          {/* Assets */}
          <Card>
            <CardHeader>
              <CardTitle>設備清單</CardTitle>
              <CardDescription>
                列出公司重要的電腦和伺服器，並說明它們的用途
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {/* Existing Assets */}
              <div className="space-y-3">
                {profile.assets.map((asset) => (
                  <div
                    key={asset.id}
                    className="flex items-center gap-4 rounded-lg border border-border bg-muted/30 p-4"
                  >
                    <div className="flex-1 space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-sm font-medium">
                          {asset.name}
                        </span>
                        <Badge
                          className={criticalityLabels[asset.criticality].color}
                        >
                          {criticalityLabels[asset.criticality].label}
                        </Badge>
                      </div>
                      <p className="text-sm text-muted-foreground">
                        {asset.purpose}
                      </p>
                    </div>
                    <Button
                      variant="ghost"
                      size="icon"
                      onClick={() => handleRemoveAsset(asset.id)}
                      className="text-muted-foreground hover:text-destructive"
                    >
                      <Trash2 className="size-4" />
                    </Button>
                  </div>
                ))}
              </div>

              {/* Add New Asset */}
              <div className="rounded-lg border border-dashed border-border p-4">
                <p className="mb-3 text-sm font-medium">新增設備</p>
                <div className="grid gap-3 sm:grid-cols-4">
                  <Input
                    value={newAsset.name}
                    onChange={(e) =>
                      setNewAsset((prev) => ({ ...prev, name: e.target.value }))
                    }
                    placeholder="設備名稱（如 pos-*）"
                    className="sm:col-span-1"
                  />
                  <Input
                    value={newAsset.purpose}
                    onChange={(e) =>
                      setNewAsset((prev) => ({ ...prev, purpose: e.target.value }))
                    }
                    placeholder="用途說明（如 收銀機）"
                    className="sm:col-span-2"
                  />
                  <div className="flex gap-2">
                    <select
                      value={newAsset.criticality}
                      onChange={(e) =>
                        setNewAsset((prev) => ({
                          ...prev,
                          criticality: e.target.value as Asset["criticality"],
                        }))
                      }
                      className="flex-1 rounded-md border border-input bg-background px-3 py-2 text-sm"
                    >
                      <option value="critical">極重要</option>
                      <option value="high">重要</option>
                      <option value="medium">一般</option>
                      <option value="low">次要</option>
                    </select>
                    <Button onClick={handleAddAsset} size="icon">
                      <Plus className="size-4" />
                    </Button>
                  </div>
                </div>
                <p className="mt-2 text-xs text-muted-foreground">
                  設備名稱可以用 * 代表多台，例如 pos-* 代表所有收銀機
                </p>
              </div>
            </CardContent>
          </Card>

          {/* Risk Notes */}
          <Card>
            <CardHeader>
              <CardTitle>特別注意事項</CardTitle>
              <CardDescription>
                寫下任何您認為重要的資安規則，系統會特別留意
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Textarea
                value={profile.riskNotes}
                onChange={(e) =>
                  setProfile((prev) => ({ ...prev, riskNotes: e.target.value }))
                }
                placeholder="例如：&#10;• 信用卡資料只應存在於財務資料庫&#10;• 非上班時間的管理者登入需特別注意&#10;• 開發環境不應存取正式資料庫"
                rows={5}
              />
              <p className="mt-2 text-xs text-muted-foreground">
                每行一條規則，越具體越好。這些會讓 AI 在分析告警時更準確
              </p>
            </CardContent>
          </Card>
        </div>
      </main>
    </div>
  );
}

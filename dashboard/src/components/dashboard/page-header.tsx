"use client";

import type { LucideIcon } from "lucide-react";
import type { ReactNode } from "react";
import { ThemeToggle } from "@/components/dashboard/theme-toggle";

interface PageHeaderProps {
  icon: LucideIcon;
  title: ReactNode;
  description?: ReactNode;
  /** 右側自訂動作（例如「重新整理」按鈕）；ThemeToggle 一律自動附加在最後 */
  actions?: ReactNode;
}

// 全站共用的頁首：左側圖示 + 標題/說明，右側動作 + 主題切換。
// 統一各頁的字級、間距與排版，避免每頁各自手寫造成樣式漂移。
export function PageHeader({ icon: Icon, title, description, actions }: PageHeaderProps) {
  return (
    <header className="flex items-center justify-between border-b border-border bg-card px-6 py-4">
      <div className="flex items-center gap-3">
        <div className="flex size-10 items-center justify-center rounded-lg bg-primary/10">
          <Icon className="size-5 text-primary" />
        </div>
        <div>
          <h1 className="text-xl font-semibold">{title}</h1>
          {description && (
            <p className="text-sm text-muted-foreground">{description}</p>
          )}
        </div>
      </div>
      <div className="flex items-center gap-2">
        {actions}
        <ThemeToggle />
      </div>
    </header>
  );
}

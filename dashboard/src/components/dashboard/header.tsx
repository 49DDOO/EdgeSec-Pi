"use client";

import { Shield, Bell, Settings } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ThemeToggle } from "./theme-toggle";

interface HeaderProps {
  pendingCount: number;
  onNotificationClick?: () => void;
}

export function Header({ pendingCount, onNotificationClick }: HeaderProps) {
  return (
    <header className="sticky top-0 z-50 border-b bg-card/95 backdrop-blur supports-[backdrop-filter]:bg-card/60">
      <div className="flex h-16 items-center justify-between px-4 md:px-6">
        <div className="flex items-center gap-3">
          <div className="flex size-10 items-center justify-center rounded-lg bg-primary">
            <Shield className="size-6 text-primary-foreground" />
          </div>
          <div className="flex flex-col">
            <h1 className="text-lg font-semibold tracking-tight">EdgeSec-Pi</h1>
            <p className="text-xs text-muted-foreground">資安監控中心</p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <Button
            variant="ghost"
            size="icon"
            className="relative size-9"
            onClick={onNotificationClick}
          >
            <Bell className="size-5" />
            {pendingCount > 0 && (
              <Badge
                variant="destructive"
                className="absolute -right-1 -top-1 flex size-5 items-center justify-center rounded-full p-0 text-xs"
              >
                {pendingCount > 9 ? "9+" : pendingCount}
              </Badge>
            )}
            <span className="sr-only">通知</span>
          </Button>
          <ThemeToggle />
          <Button variant="ghost" size="icon" className="size-9">
            <Settings className="size-5" />
            <span className="sr-only">設定</span>
          </Button>
        </div>
      </div>
    </header>
  );
}

"use client";

import { Bell } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ThemeToggle } from "@/components/dashboard/theme-toggle";

interface DashboardPageHeaderProps {
  title: string;
  description: string;
  ownerPendingCount: number;
  onOpenNotifications: () => void;
}

export function DashboardPageHeader({
  description,
  onOpenNotifications,
  ownerPendingCount,
  title,
}: DashboardPageHeaderProps) {
  return (
    <header className="flex items-center justify-between border-b border-border bg-card px-6 py-4">
      <div>
        <h1 className="text-xl font-semibold">{title}</h1>
        <p className="text-sm text-muted-foreground">{description}</p>
      </div>
      <div className="flex items-center gap-2">
        <Button
          variant="outline"
          size="icon"
          className="relative"
          onClick={onOpenNotifications}
        >
          <Bell className="size-4" />
          {ownerPendingCount > 0 && (
            <span className="absolute -right-1 -top-1 flex size-5 items-center justify-center rounded-full bg-destructive text-xs text-destructive-foreground">
              {ownerPendingCount}
            </span>
          )}
        </Button>
        <ThemeToggle />
      </div>
    </header>
  );
}

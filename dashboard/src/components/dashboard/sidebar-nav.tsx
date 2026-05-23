"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard,
  Bell,
  Monitor,
  TestTube2,
  Shield,
  ServerCog,
  ChevronLeft,
  ChevronRight,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { useState } from "react";

const navItems = [
  {
    title: "資安總覽",
    href: "/",
    icon: LayoutDashboard,
    description: "查看公司整體資安狀況",
  },
  {
    title: "通知設定",
    href: "/settings/notifications",
    icon: Bell,
    description: "LINE、Slack、Email 通知",
  },
  {
    title: "設備管理",
    href: "/settings/endpoints",
    icon: Monitor,
    description: "監控設備與 Agent 狀態",
  },
  {
    title: "測試中心",
    href: "/settings/testing",
    icon: TestTube2,
    description: "測試通知與 Wazuh Sample Data",
  },
  {
    title: "系統狀態",
    href: "/settings/status",
    icon: ServerCog,
    description: "查看 Bridge、Wazuh、AI 與通知是否正常",
  },
];

export function SidebarNav() {
  const pathname = usePathname();
  const [collapsed, setCollapsed] = useState(false);

  return (
    <aside
      className={cn(
        "flex h-screen flex-col border-r border-border bg-card transition-all duration-300",
        collapsed ? "w-16" : "w-64"
      )}
    >
      {/* Logo / Brand */}
      <div className="flex h-16 items-center gap-2 border-b border-border px-4">
        <div className="flex size-9 items-center justify-center rounded-lg bg-primary">
          <Shield className="size-5 text-primary-foreground" />
        </div>
        {!collapsed && (
          <div className="flex flex-col">
            <span className="text-sm font-semibold">EdgeSec-Pi</span>
            <span className="text-xs text-muted-foreground">資安監控中心</span>
          </div>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 space-y-1 p-2">
        {navItems.map((item) => {
          const isActive =
            pathname === item.href ||
            (item.href !== "/" && pathname.startsWith(item.href));

          const linkContent = (
            <Link
              href={item.href}
              className={cn(
                "flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors",
                isActive
                  ? "bg-primary/10 text-primary"
                  : "text-muted-foreground hover:bg-muted hover:text-foreground"
              )}
            >
              <item.icon className="size-5 shrink-0" />
              {!collapsed && <span>{item.title}</span>}
            </Link>
          );

          if (collapsed) {
            return (
              <Tooltip key={item.href}>
                <TooltipTrigger render={linkContent} />
                <TooltipContent side="right" className="flex flex-col gap-1">
                  <span className="font-medium">{item.title}</span>
                  <span className="text-xs text-muted-foreground">
                    {item.description}
                  </span>
                </TooltipContent>
              </Tooltip>
            );
          }

          return <div key={item.href}>{linkContent}</div>;
        })}
      </nav>

      {/* Collapse Toggle */}
      <div className="border-t border-border p-2">
        <Button
          variant="ghost"
          size="sm"
          onClick={() => setCollapsed(!collapsed)}
          className="w-full justify-center"
        >
          {collapsed ? (
            <ChevronRight className="size-4" />
          ) : (
            <>
              <ChevronLeft className="size-4" />
              <span className="ml-2">收合選單</span>
            </>
          )}
        </Button>
      </div>
    </aside>
  );
}

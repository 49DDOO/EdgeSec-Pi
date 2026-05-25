"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard,
  Bell,
  Download,
  Monitor,
  Shield,
  ServerCog,
  ChevronLeft,
  ChevronRight,
  AlertCircle,
  SlidersHorizontal,
  BrainCircuit,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { useEffect, useState } from "react";

const navSections = [
  {
    title: "營運",
    items: [
      {
        title: "今日待辦",
        href: "/",
        icon: LayoutDashboard,
        description: "需要老闆決定的事項",
      },
      {
        title: "告警紀錄",
        href: "/?tab=alerts",
        icon: AlertCircle,
        description: "IT 查詢告警事件",
      },
    ],
  },
  {
    title: "電腦",
    items: [
      {
        title: "電腦背景",
        href: "/settings/endpoints?section=inventory",
        icon: Monitor,
        description: "端點狀態與業務用途",
      },
      {
        title: "電腦安裝",
        href: "/settings/endpoints?section=install",
        icon: Download,
        description: "下載與複製 Agent 安裝方式",
      },
    ],
  },
  {
    title: "設定",
    items: [
      {
        title: "偵測類別",
        href: "/settings/detections",
        icon: SlidersHorizontal,
        description: "告警紀錄分頁與類別顯示",
      },
      {
        title: "AI模型設定",
        href: "/settings/ai-model",
        icon: BrainCircuit,
        description: "本地或雲端模型",
      },
      {
        title: "通知設定",
        href: "/settings/notifications",
        icon: Bell,
        description: "LINE、Slack、Email 通知",
      },
      {
        title: "系統狀態",
        href: "/settings/status",
        icon: ServerCog,
        description: "查看 Bridge、Wazuh、AI 與通知是否正常",
      },
    ],
  },
];

export function SidebarNav() {
  const pathname = usePathname();
  const [collapsed, setCollapsed] = useState(false);
  const [search, setSearch] = useState("");

  useEffect(() => {
    const timer = window.setTimeout(() => setSearch(window.location.search), 0);
    return () => window.clearTimeout(timer);
  }, [pathname]);

  const searchParams = new URLSearchParams(search);
  const tab = searchParams.get("tab");
  const section = searchParams.get("section");

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
        {navSections.map((group) => (
          <div key={group.title} className="space-y-1 py-1">
            {!collapsed && (
              <div className="px-3 pb-1 pt-2 text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
                {group.title}
              </div>
            )}
            {group.items.map((item) => {
              const [hrefPath, hrefQuery = ""] = item.href.split("?");
              const itemParams = new URLSearchParams(hrefQuery);
              const itemTab = itemParams.get("tab");
              const itemSection = itemParams.get("section");
              const isActive =
                item.href === "/"
                  ? pathname === "/" && !tab
                  : itemTab
                    ? pathname === hrefPath && tab === itemTab
                    : itemSection
                      ? pathname === hrefPath && (section === itemSection || (!section && itemSection === "inventory"))
                      : pathname === hrefPath || pathname.startsWith(`${hrefPath}/`);

              const linkClassName = cn(
                "flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors",
                isActive
                  ? "bg-primary/10 text-primary"
                  : "text-muted-foreground hover:bg-muted hover:text-foreground"
              );
              const inner = (
                <>
                  <item.icon className="size-5 shrink-0" />
                  {!collapsed && <span>{item.title}</span>}
                </>
              );
              const shouldUseDocumentNavigation = item.href === "/" || item.href.includes("?");
              const linkContent = shouldUseDocumentNavigation ? (
                <a href={item.href} className={linkClassName}>
                  {inner}
                </a>
              ) : (
                <Link href={item.href} className={linkClassName}>
                  {inner}
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
          </div>
        ))}
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

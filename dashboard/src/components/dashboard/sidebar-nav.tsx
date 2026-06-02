"use client";

import Link from "next/link";
import { usePathname, useSearchParams } from "next/navigation";
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
  BrainCircuit,
  Database,
  ClipboardCheck,
  MessageSquareText,
  TestTube2,
  ChevronDown,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { useIsMobile } from "@/hooks/use-mobile";
import { useState } from "react";

type NavChild = {
  title: string;
  href?: string;
  children?: NavChild[];
};

const navSections = [
  {
    title: "日常處理",
    items: [
      {
        title: "Agent 總覽",
        href: "/",
        icon: LayoutDashboard,
        description: "Agent 狀態、請示與能力",
      },
      {
        title: "調查紀錄",
        href: "/events",
        icon: AlertCircle,
        description: "Agent 判斷後的安全事件",
      },
      {
        title: "證據查詢",
        href: "/investigation",
        icon: MessageSquareText,
        description: "向 Agent 查詢已接來源證據",
      },
    ],
  },
  {
    title: "資產管理",
    items: [
      {
        title: "受保護資產",
        href: "/settings/endpoints?section=inventory",
        icon: Monitor,
        description: "端點、帳號與業務用途",
      },
      {
        title: "Agent 部署",
        href: "/settings/endpoints?section=install",
        icon: Download,
        description: "部署地端感測與回應能力",
      },
    ],
  },
  {
    title: "上線與健檢",
    items: [
      {
        title: "首次設定",
        href: "/settings/setup",
        icon: ClipboardCheck,
        description: "按步驟完成上線",
      },
      {
        title: "Agent 健康",
        href: "/settings/status",
        icon: ServerCog,
        description: "來源、AI、通知與佇列狀態",
      },
      {
        title: "流程測試",
        href: "/settings/testing",
        icon: TestTube2,
        description: "送測試訊號確認 Agent 流程",
      },
    ],
  },
  {
    title: "設定",
    items: [
      {
        title: "Sources",
        href: "/settings/sources",
        icon: Database,
        description: "管理雲端與地端資料來源",
        children: [
          { title: "總覽", href: "/settings/sources" },
          {
            title: "端點偵測",
            children: [
              { title: "Wazuh", href: "/settings/sources/wazuh" },
            ],
          },
          {
            title: "雲端身分",
            children: [
              { title: "Google Workspace", href: "/settings/sources/google_workspace" },
              { title: "Microsoft 365", href: "/settings/sources/microsoft_365" },
            ],
          },
          {
            title: "網路邊界",
            children: [
              { title: "Firewall / Edge", href: "/settings/sources/firewall" },
            ],
          },
          {
            title: "端點事件",
            children: [
              { title: "EDR", href: "/settings/sources/edr" },
            ],
          },
        ],
      },
      {
        title: "Agent 大腦",
        href: "/settings/ai-model",
        icon: BrainCircuit,
        description: "本地或雲端判斷模型",
      },
      {
        title: "通知設定",
        href: "/settings/notifications",
        icon: Bell,
        description: "LINE、Slack、Telegram、Email 通知",
      },
    ],
  },
];

function childIsActive(child: NavChild, pathname: string): boolean {
  const hrefActive = child.href
    ? pathname === child.href
      || (child.href !== "/settings/sources" && pathname.startsWith(`${child.href}/`))
    : false;
  return Boolean(
    hrefActive
      || child.children?.some((item) => childIsActive(item, pathname))
  );
}

function SourceTreeItem({
  child,
  depth = 0,
  pathname,
}: {
  child: NavChild;
  depth?: number;
  pathname: string;
}) {
  const active = childIsActive(child, pathname);
  if (!child.href) {
    return (
      <div className="space-y-1">
        <div className="px-1 pb-0.5 pt-2 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground/70">
          {child.title}
        </div>
        <div className={cn("space-y-1", depth > 0 && "ml-1")}>
          {child.children?.map((item) => (
            <SourceTreeItem key={`${child.title}-${item.title}`} child={item} depth={depth + 1} pathname={pathname} />
          ))}
        </div>
      </div>
    );
  }

  return (
    <Link
      href={child.href}
      className={cn(
        "block rounded-md px-2 py-1.5 text-xs font-medium transition-colors",
        depth > 0 && "ml-1",
        active
          ? "bg-primary/10 text-primary"
          : "text-muted-foreground hover:bg-muted hover:text-foreground"
      )}
    >
      {child.title}
    </Link>
  );
}

export function SidebarNav() {
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const isMobile = useIsMobile();
  // null = 尚未手動切換：窄螢幕預設收合成圖示列，避免吃掉內容寬度；使用者切換後以其選擇為準。
  const [manualCollapsed, setManualCollapsed] = useState<boolean | null>(null);
  const [openTrees, setOpenTrees] = useState<Record<string, boolean>>({
    "/settings/sources": true,
  });
  const collapsed = manualCollapsed ?? isMobile;

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
            <span className="text-xs text-muted-foreground">資安 Agent Dashboard</span>
          </div>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 space-y-1 overflow-y-auto p-2">
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
              const itemSection = itemParams.get("section");
              const isActive =
                item.href === "/"
                  ? pathname === "/" && !tab
                  : itemSection
                        ? pathname === hrefPath && (section === itemSection || (!section && itemSection === "inventory"))
                      : (item.href === "/settings/sources" && (pathname === "/settings/wazuh" || pathname.startsWith("/settings/sources")))
                        || pathname === hrefPath
                        || pathname.startsWith(`${hrefPath}/`);
              const childItems = "children" in item ? item.children : undefined;
              const hasChildren = Boolean(childItems?.length);
              const treeOpen = openTrees[item.href] ?? isActive;
              const showChildren = !collapsed && hasChildren && isActive && treeOpen;

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
              // 全部走 client-side 導覽：頁面以 useSearchParams 反應 query 變化，
              // 不需要整頁重載（避免閃白屏）。
              const linkContent = hasChildren && !collapsed ? (
                <div
                  className={cn(
                    "flex items-center rounded-lg text-sm font-medium transition-colors",
                    isActive
                      ? "bg-primary/10 text-primary"
                      : "text-muted-foreground hover:bg-muted hover:text-foreground"
                  )}
                >
                  <Link href={item.href} className="flex min-w-0 flex-1 items-center gap-3 px-3 py-2.5">
                    {inner}
                  </Link>
                  <button
                    type="button"
                    aria-label={treeOpen ? `收合${item.title}` : `展開${item.title}`}
                    aria-expanded={treeOpen}
                    className="mr-2 flex size-7 shrink-0 items-center justify-center rounded-md text-muted-foreground hover:bg-background/70 hover:text-foreground"
                    onClick={() =>
                      setOpenTrees((current) => ({
                        ...current,
                        [item.href]: !treeOpen,
                      }))
                    }
                  >
                    <ChevronDown
                      className={cn(
                        "size-3.5 transition-transform",
                        !treeOpen && "-rotate-90"
                      )}
                    />
                  </button>
                </div>
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

              return (
                <div key={item.href}>
                  {linkContent}
                  {showChildren && (
                    <div className="ml-8 mt-1 space-y-1">
                      {childItems?.map((child) => {
                        return (
                          <SourceTreeItem
                            key={child.href || child.title}
                            child={child}
                            pathname={pathname}
                          />
                        );
                      })}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        ))}
      </nav>

      {/* Collapse Toggle */}
      <div className="border-t border-border p-2">
        <Button
          variant="ghost"
          size="sm"
          onClick={() => setManualCollapsed(!collapsed)}
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

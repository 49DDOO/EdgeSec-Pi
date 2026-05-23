import type { Metadata, Viewport } from "next";
import { ThemeProvider } from "@/components/theme-provider";
import { TooltipProvider } from "@/components/ui/tooltip";
import { Toaster } from "@/components/ui/sonner";
import { SidebarNav } from "@/components/dashboard/sidebar-nav";
import "./globals.css";

export const metadata: Metadata = {
  title: "EdgeSec-Pi Dashboard | 資安監控中心",
  description: "中小企業資安告警監控與回應系統 - Wazuh LLM Bridge",
};

export const viewport: Viewport = {
  themeColor: [
    { media: "(prefers-color-scheme: light)", color: "#f8fafc" },
    { media: "(prefers-color-scheme: dark)", color: "#0f172a" },
  ],
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="zh-TW"
      className="h-full antialiased"
      suppressHydrationWarning
    >
      <body className="h-full bg-background">
        <ThemeProvider
          attribute="class"
          defaultTheme="system"
          enableSystem
          disableTransitionOnChange
        >
          <TooltipProvider>
            <div className="flex h-full">
              <SidebarNav />
              <main className="flex-1 overflow-auto">
                {children}
              </main>
            </div>
          </TooltipProvider>
          <Toaster position="top-right" richColors />
        </ThemeProvider>
      </body>
    </html>
  );
}

import { AlertTriangle } from "lucide-react";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";

export function DashboardDataError({ message }: { message: string }) {
  return (
    <div className="rounded-lg border border-destructive/30 bg-destructive/5 p-6">
      <h2 className="text-lg font-semibold text-destructive">Dashboard 資料讀取失敗</h2>
      <p className="mt-2 text-sm text-muted-foreground">
        目前不顯示示範資料，避免誤判正式狀態。請先確認 EdgeSec-Pi bridge 是否正常啟動。
      </p>
      <code className="mt-4 block rounded-md bg-muted px-3 py-2 text-sm text-muted-foreground">
        {message}
      </code>
    </div>
  );
}

export function DashboardHomeSkeleton() {
  return (
    <div className="space-y-6">
      <div className="grid gap-4 md:grid-cols-4">
        {Array.from({ length: 4 }).map((_, index) => (
          <Card key={index}>
            <CardHeader className="space-y-2 pb-2">
              <Skeleton className="h-4 w-24" />
              <Skeleton className="h-7 w-16" />
            </CardHeader>
            <CardContent>
              <Skeleton className="h-3 w-32" />
            </CardContent>
          </Card>
        ))}
      </div>
      <Card>
        <CardHeader className="space-y-2">
          <Skeleton className="h-5 w-40" />
          <Skeleton className="h-4 w-72 max-w-full" />
        </CardHeader>
        <CardContent>
          <div className="grid gap-3 lg:grid-cols-4">
            {Array.from({ length: 4 }).map((_, index) => (
              <Skeleton key={index} className="h-36 rounded-lg" />
            ))}
          </div>
        </CardContent>
      </Card>
      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader className="space-y-2">
            <Skeleton className="h-5 w-36" />
            <Skeleton className="h-4 w-64 max-w-full" />
          </CardHeader>
          <CardContent className="space-y-4">
            {Array.from({ length: 3 }).map((_, index) => (
              <div key={index} className="space-y-3">
                <Skeleton className="h-5 w-3/4" />
                <Skeleton className="h-16 w-full" />
              </div>
            ))}
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="space-y-2">
            <Skeleton className="h-5 w-36" />
            <Skeleton className="h-4 w-56 max-w-full" />
          </CardHeader>
          <CardContent className="space-y-3">
            {Array.from({ length: 5 }).map((_, index) => (
              <Skeleton key={index} className="h-12 w-full" />
            ))}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

export function DashboardEventsSkeleton() {
  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="space-y-2">
          <Skeleton className="h-4 w-28" />
          <Skeleton className="h-3 w-64 max-w-full" />
        </div>
        <Skeleton className="h-9 w-44" />
      </div>
      <Skeleton className="h-72 w-full rounded-lg" />
      <Card>
        <CardHeader className="space-y-2">
          <Skeleton className="h-5 w-28" />
          <Skeleton className="h-4 w-72 max-w-full" />
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex flex-wrap gap-2">
            {Array.from({ length: 5 }).map((_, index) => (
              <Skeleton key={index} className="h-9 w-24" />
            ))}
          </div>
          {Array.from({ length: 7 }).map((_, index) => (
            <div key={index} className="grid gap-3 rounded-md border p-3 md:grid-cols-[110px_1fr_140px_110px_80px_40px]">
              <Skeleton className="h-6 w-20" />
              <div className="space-y-2">
                <Skeleton className="h-4 w-3/4" />
                <Skeleton className="h-3 w-1/2" />
              </div>
              <Skeleton className="h-5 w-24" />
              <Skeleton className="h-5 w-24" />
              <Skeleton className="h-5 w-16" />
              <Skeleton className="h-8 w-8" />
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}

export function DashboardFallbackHeader({ title }: { title: string }) {
  return (
    <div className="flex h-full flex-col">
      <header className="flex items-center justify-between border-b border-border bg-card px-6 py-4">
        <div>
          <h1 className="text-xl font-semibold">{title}</h1>
          <p className="text-sm text-muted-foreground">正在載入 Dashboard 資料</p>
        </div>
        <AlertTriangle className="size-5 text-muted-foreground" />
      </header>
      <main className="flex-1 overflow-auto p-6">
        {title === "事件中心" ? <DashboardEventsSkeleton /> : <DashboardHomeSkeleton />}
      </main>
    </div>
  );
}

"use client";

import { useMemo, useState } from "react";
import { CartesianGrid, Line, LineChart, XAxis, YAxis } from "recharts";
import { ChevronDown, ChevronUp } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { ChartContainer, ChartTooltip, type ChartConfig } from "@/components/ui/chart";
import type { AlertTrend } from "@/lib/types";

interface AlertTrendChartProps {
  data: AlertTrend[];
  selectedEndpoint?: string;
}

const COLORS = [
  "var(--primary)",
  "var(--color-high)",
  "var(--color-medium)",
  "var(--color-success)",
  "var(--color-critical)",
  "var(--color-low)",
];

function endpointTotal(item: AlertTrend, endpoint: string) {
  return Number(item.endpoints?.[endpoint] || 0);
}

function totalForDay(item: AlertTrend, selectedEndpoint: string) {
  if (selectedEndpoint !== "all") return endpointTotal(item, selectedEndpoint);
  return Object.values(item.endpoints || {}).reduce((sum, value) => sum + Number(value || 0), 0);
}

function EndpointTrendTooltip({
  active,
  payload,
  label,
  endpointNames,
}: {
  active?: boolean;
  payload?: Array<{ payload?: Record<string, unknown> & { endpoints?: Record<string, number>; total?: number } }>;
  label?: string;
  endpointNames: string[];
}) {
  if (!active || !payload?.length) return null;
  const item = payload[0].payload;
  if (!item) return null;
  const rows = endpointNames
    .map((name) => [name, Number(item.endpoints?.[name] || 0)] as const)
    .filter(([, value]) => value > 0)
    .sort((a, b) => b[1] - a[1]);

  return (
    <div className="rounded-lg border bg-popover p-3 text-sm shadow-md">
      <div className="font-medium">{label}</div>
      <div className="mt-1 text-muted-foreground">總事件 {Number(item.total || 0)} 件</div>
      {rows.length > 0 ? (
        <div className="mt-2 grid grid-cols-[auto_auto] gap-x-5 gap-y-1">
          {rows.map(([name, value]) => (
            <div key={name} className="contents">
              <span className="max-w-56 truncate text-muted-foreground">{name}</span>
              <span className="text-right font-medium">{value}</span>
            </div>
          ))}
        </div>
      ) : (
        <div className="mt-2 text-muted-foreground">當天沒有端點事件</div>
      )}
    </div>
  );
}

export function AlertTrendChart({ data, selectedEndpoint = "all" }: AlertTrendChartProps) {
  const [expanded, setExpanded] = useState(false);
  const endpointTotals = useMemo(() => {
    const totals = new Map<string, number>();
    data.forEach((item) => {
      Object.entries(item.endpoints || {}).forEach(([endpoint, count]) => {
        totals.set(endpoint, (totals.get(endpoint) || 0) + Number(count || 0));
      });
    });
    return Array.from(totals.entries()).sort((a, b) => b[1] - a[1]);
  }, [data]);
  const visibleEndpoints = useMemo(
    () => selectedEndpoint === "all"
      ? endpointTotals.slice(0, 6).map(([endpoint]) => endpoint)
      : [selectedEndpoint],
    [endpointTotals, selectedEndpoint]
  );
  const series = visibleEndpoints.map((endpoint, index) => ({
    name: endpoint,
    key: `endpoint_${index}`,
    color: COLORS[index % COLORS.length],
  }));
  const chartData = useMemo(
    () => data.map((item) => {
      const row: Record<string, number | string | Record<string, number>> = {
        date: item.date,
        total: totalForDay(item, selectedEndpoint),
        endpoints: item.endpoints || {},
      };
      visibleEndpoints.forEach((endpoint, index) => {
        row[`endpoint_${index}`] = endpointTotal(item, endpoint);
      });
      return row;
    }),
    [data, selectedEndpoint, visibleEndpoints]
  );
  const chartConfig = Object.fromEntries(
    series.map((item) => [item.key, { label: item.name, color: item.color }])
  ) satisfies ChartConfig;
  const total = chartData.reduce((sum, item) => sum + Number(item.total || 0), 0);
  const activeDays = chartData.filter((item) => Number(item.total || 0) > 0).length;
  const topEndpoint: [string, number] | undefined = selectedEndpoint === "all"
    ? endpointTotals[0]
    : [selectedEndpoint, total];

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between gap-4">
        <div>
          <CardTitle>端點事件趨勢</CardTitle>
          <CardDescription>
            過去 {data.length || 7} 天共 {total} 件，{activeDays} 天有事件
            {topEndpoint && topEndpoint[1] > 0
              ? `；${selectedEndpoint === "all" ? "最多是" : "目前查看"} ${topEndpoint[0]} 的 ${topEndpoint[1]} 件`
              : ""}
          </CardDescription>
        </div>
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={() => setExpanded((value) => !value)}
        >
          {expanded ? (
            <ChevronUp data-icon="inline-start" />
          ) : (
            <ChevronDown data-icon="inline-start" />
          )}
          {expanded ? "收合趨勢" : "展開趨勢"}
        </Button>
      </CardHeader>
      {expanded && (
        <CardContent>
          <div className="mb-3 text-sm text-muted-foreground">
            每條線代表一台端點每天被通報的事件數；端點篩選會同步改變這張圖。
          </div>
          {series.length > 0 && (
            <div className="mb-3 flex flex-wrap gap-x-4 gap-y-2 text-xs text-muted-foreground">
              {series.map((item) => (
                <div key={item.key} className="flex min-w-0 items-center gap-2">
                  <span
                    className="size-2.5 shrink-0 rounded-full"
                    style={{ backgroundColor: item.color }}
                    aria-hidden="true"
                  />
                  <span className="max-w-56 truncate">{item.name}</span>
                </div>
              ))}
            </div>
          )}
          <ChartContainer config={chartConfig} className="h-[240px] w-full">
            <LineChart
              data={chartData}
              margin={{ top: 10, right: 10, left: 0, bottom: 0 }}
            >
              <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
              <XAxis
                dataKey="date"
                tickLine={false}
                axisLine={false}
                tickMargin={8}
                className="text-xs fill-muted-foreground"
              />
              <YAxis
                tickLine={false}
                axisLine={false}
                tickMargin={8}
                className="text-xs fill-muted-foreground"
              />
              <ChartTooltip
                content={<EndpointTrendTooltip endpointNames={visibleEndpoints} />}
                cursor={{ stroke: "var(--border)" }}
              />
              {series.map((item) => (
                <Line
                  key={item.key}
                  type="monotone"
                  dataKey={item.key}
                  name={item.name}
                  stroke={item.color}
                  strokeWidth={2}
                  dot={{ r: 3 }}
                  activeDot={{ r: 5 }}
                />
              ))}
            </LineChart>
          </ChartContainer>
          {total === 0 && (
            <p className="mt-3 text-sm text-muted-foreground">這段時間沒有端點事件。</p>
          )}
          {selectedEndpoint === "all" && endpointTotals.length > visibleEndpoints.length && (
            <p className="mt-3 text-xs text-muted-foreground">
              為了保持圖表可讀性，只顯示事件最多的前 {visibleEndpoints.length} 台端點；可用上方端點篩選查看單一端點。
            </p>
          )}
        </CardContent>
      )}
    </Card>
  );
}

"use client";

import { Area, AreaChart, CartesianGrid, XAxis, YAxis } from "recharts";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ChartContainer, ChartTooltip, ChartTooltipContent, type ChartConfig } from "@/components/ui/chart";
import type { AlertTrend } from "@/lib/types";

interface AlertTrendChartProps {
  data: AlertTrend[];
}

const chartConfig = {
  critical: {
    label: "危急",
    color: "var(--color-critical)",
  },
  high: {
    label: "高",
    color: "var(--color-high)",
  },
  medium: {
    label: "中",
    color: "var(--color-medium)",
  },
  low: {
    label: "低",
    color: "var(--color-low)",
  },
} satisfies ChartConfig;

export function AlertTrendChart({ data }: AlertTrendChartProps) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>告警趨勢</CardTitle>
        <CardDescription>過去 7 天的告警數量變化</CardDescription>
      </CardHeader>
      <CardContent>
        <ChartContainer config={chartConfig} className="h-[300px] w-full">
          <AreaChart
            data={data}
            margin={{ top: 10, right: 10, left: 0, bottom: 0 }}
          >
            <defs>
              <linearGradient id="fillCritical" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="var(--color-critical)" stopOpacity={0.8} />
                <stop offset="95%" stopColor="var(--color-critical)" stopOpacity={0.1} />
              </linearGradient>
              <linearGradient id="fillHigh" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="var(--color-high)" stopOpacity={0.8} />
                <stop offset="95%" stopColor="var(--color-high)" stopOpacity={0.1} />
              </linearGradient>
              <linearGradient id="fillMedium" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="var(--color-medium)" stopOpacity={0.8} />
                <stop offset="95%" stopColor="var(--color-medium)" stopOpacity={0.1} />
              </linearGradient>
              <linearGradient id="fillLow" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="var(--color-low)" stopOpacity={0.8} />
                <stop offset="95%" stopColor="var(--color-low)" stopOpacity={0.1} />
              </linearGradient>
            </defs>
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
              content={<ChartTooltipContent />}
              cursor={{ fill: "var(--color-muted)", opacity: 0.3 }}
            />
            <Area
              type="monotone"
              dataKey="critical"
              stroke="var(--color-critical)"
              fill="url(#fillCritical)"
              strokeWidth={2}
              stackId="1"
            />
            <Area
              type="monotone"
              dataKey="high"
              stroke="var(--color-high)"
              fill="url(#fillHigh)"
              strokeWidth={2}
              stackId="1"
            />
            <Area
              type="monotone"
              dataKey="medium"
              stroke="var(--color-medium)"
              fill="url(#fillMedium)"
              strokeWidth={2}
              stackId="1"
            />
            <Area
              type="monotone"
              dataKey="low"
              stroke="var(--color-low)"
              fill="url(#fillLow)"
              strokeWidth={2}
              stackId="1"
            />
          </AreaChart>
        </ChartContainer>
      </CardContent>
    </Card>
  );
}

// src/components/DashboardMetrics.tsx
"use client";

import useMetrics from "@/hooks/useMetrics";
import { MetricCard } from "@/components/ui/MetricCard";

export function DashboardMetrics() {
  const { data, isLoading } = useMetrics();

  if (isLoading) {
    return <p className="text-3xl text-center">Loading real-time data...</p>;
  }

  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-8 mb-12">
      <MetricCard
        title="Revenue"
        value={`£${data.revenue.total.toLocaleString()}`}
        trend={data.revenue.trend}
      />
      <MetricCard
        title="Churn Rate"
        value={`${data.churn.rate}%`}
        trend={`${data.churn.at_risk} at risk`}
        color="red"
      />
      <MetricCard
        title="LTV:CAC"
        value={`${data.performance.ratio}:1`}
        trend="Healthy"
      />
    </div>
  );
}
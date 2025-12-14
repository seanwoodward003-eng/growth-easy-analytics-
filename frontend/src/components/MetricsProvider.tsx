// src/components/MetricsProvider.tsx
"use client";  // Required because it uses SWR (client hook)

import useMetrics from "@/hooks/useMetrics";
import { MetricCard } from "@/components/ui/MetricCard";
// Import other UI components you use for metrics (charts, etc.) if needed

interface MetricsProviderProps {
  children?: React.ReactNode;  // Optional: if you want to pass custom children
}

export function MetricsProvider({ children }: MetricsProviderProps) {
  const { data, isLoading, error } = useMetrics();

  if (isLoading) {
    return <p className="text-center text-3xl text-cyber-neon">Loading real-time data...</p>;
  }

  if (error) {
    return <p className="text-center text-3xl text-red-500">Error loading metrics</p>;
  }

  // Render your metric UI here — or pass data to children via context if more advanced
  return (
    <>
      {/* Example for main dashboard — adjust for each page */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-8 mb-12">
        <MetricCard title="Revenue" value={`£${data.revenue.total.toLocaleString()}`} trend={data.revenue.trend} />
        <MetricCard title="Churn Rate" value={`${data.churn.rate}%`} trend={`${data.churn.at_risk} at risk`} color="red" />
        <MetricCard title="LTV:CAC" value={`${data.performance.ratio}:1`} trend="Healthy" />
      </div>

      {/* Add your charts here if shared */}
      {children}
    </>
  );
}
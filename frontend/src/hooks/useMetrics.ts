"use client";  // ← This line is REQUIRED because useSWR is a client-side hook

import useSWR from "swr";

const fetcher = (url: string) =>
  fetch(url, { credentials: "include" }).then((r) => r.json());

export default function useMetrics() {
  const { data, error, isLoading } = useSWR(
    "https://growth-easy-analytics-2.onrender.com/api/metrics",
    fetcher,
    {
      refreshInterval: 30000,
      fallbackData: {
        revenue: { total: 12700, trend: "+6%" },
        churn: { rate: 3.2, at_risk: 18 },
        acquisition: { cac: 87, top_channel: "Organic" },
        performance: { ratio: "3.4" },
        ai_insight: "Scale organic content marketing this month.",
      },
    }
  );

  return { data, isLoading, error };
}
// src/components/RevenueMetrics.tsx
"use client";

import useMetrics from "@/hooks/useMetrics";

export function RevenueMetrics() {
  const { data } = useMetrics();

  return (
    <>
      <div className="grid md:grid-cols-2 gap-10 mb-12">
        <div className="bg-cyber-card border-2 border-green-500 rounded-2xl p-10 text-center">
          <h3 className="text-3xl">Total Revenue (30d)</h3>
          <p className="text-8xl font-bold text-green-400">
            £{data?.revenue.total ?? 12700}
          </p>
          <p className="text-3xl text-green-300 mt-4">
            {data?.revenue.trend ?? "+6%"}
          </p>
        </div>
        <div className="bg-cyber-card border-2 border-cyan-500 rounded-2xl p-10 text-center">
          <h3 className="text-3xl">Forecast Next 30d</h3>
          <p className="text-7xl font-bold text-cyber-neon">£13,800</p>
          <p className="text-2xl text-cyan-300 mt-4">+8.7% projected</p>
        </div>
      </div>

      <div className="mt-12 bg-green-900/30 border border-green-500 rounded-2xl p-10 text-center">
        <h3 className="text-3xl text-green-400 mb-4">AI Forecast</h3>
        <p className="text-2xl">
          Upsell your top 10 customers → +£3,200 recurring revenue.
        </p>
      </div>
    </>
  );
}
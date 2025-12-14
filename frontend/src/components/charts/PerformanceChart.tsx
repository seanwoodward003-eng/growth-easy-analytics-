"use client";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";

export function PerformanceChart() {
  const data = [
    { metric: "LTV", value: 162 },
    { metric: "CAC", value: 47 },
    { metric: "Ratio", value: 3.4 },
  ];

  return (
    <div className="bg-cyber-card/60 border border-yellow-500 rounded-2xl p-8">
      <h2 className="text-3xl font-bold text-yellow-400 mb-6">Performance Metrics</h2>
      <ResponsiveContainer width="100%" height={400}>
        <BarChart data={data}>
          <CartesianGrid stroke="#334455" />
          <XAxis dataKey="metric" stroke="#00ffff" />
          <YAxis stroke="#00ffff" />
          <Tooltip contentStyle={{ background: "#0a0f2c", border: "1px solid #f1c40f" }} />
          <Bar dataKey="value" fill="#f1c40f" radius={[20, 20, 0, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
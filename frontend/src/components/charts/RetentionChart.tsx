"use client";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";

export function RetentionChart() {
  const data = [
    { cohort: "Jan", "30d": 68, "60d": 51, "90d": 42 },
    { cohort: "Feb", "30d": 71, "60d": 54, "90d": 45 },
    { cohort: "Mar", "30d": 66, "60d": 49, "90d": 40 },
    { cohort: "Apr", "30d": 70, "60d": 55, "90d": 47 },
  ];

  return (
    <div className="bg-cyber-card/60 border border-purple-500 rounded-2xl p-8">
      <h2 className="text-3xl font-bold text-purple-400 mb-6">Customer Retention</h2>
      <ResponsiveContainer width="100%" height={400}>
        <BarChart data={data}>
          <CartesianGrid stroke="#334455" />
          <XAxis dataKey="cohort" stroke="#00ffff" />
          <YAxis stroke="#00ffff" />
          <Tooltip contentStyle={{ background: "#0a0f2c", border: "1px solid #9b59b6" }} />
          <Bar dataKey="30d" fill="#00ff88" />
          <Bar dataKey="60d" fill="#9b59b6" />
          <Bar dataKey="90d" fill="#ff00ff" />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
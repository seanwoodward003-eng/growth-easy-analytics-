"use client";
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";

export function RevenueChart() {
  const data = [
    { name: "Week 1", revenue: 11500 },
    { name: "Week 2", revenue: 12000 },
    { name: "Week 3", revenue: 12400 },
    { name: "Week 4", revenue: 12700 },
  ];

  return (
    <div className="bg-cyber-card/60 border border-cyber-neon rounded-2xl p-8">
      <h2 className="text-3xl font-bold text-green-400 mb-6">Revenue Trend</h2>
      <ResponsiveContainer width="100%" height={420}>
        <LineChart data={data}>
          <CartesianGrid stroke="#334455" />
          <XAxis dataKey="name" stroke="#00ffff" />
          <YAxis stroke="#00ffff" />
          <Tooltip contentStyle={{ background: "#0a0f2c", border: "1px solid #00ffff" }} />
          <Line type="monotone" dataKey="revenue" stroke="#2ecc71" strokeWidth={5} />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
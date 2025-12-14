"use client";
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";

export function CostTrendChart() {
  const data = [
    { month: "Jan", cost: 102 },
    { month: "Feb", cost: 98 },
    { month: "Mar", cost: 91 },
    { month: "Apr", cost: 87 },
    { month: "May", cost: 89 },
    { month: "Jun", cost: 87 },
  ];

  return (
    <div className="bg-cyber-card/60 border border-purple-500 rounded-2xl p-8">
      <h2 className="text-3xl font-bold text-purple-400 mb-6">Acquisition Cost Trend</h2>
      <ResponsiveContainer width="100%" height={380}>
        <AreaChart data={data}>
          <CartesianGrid stroke="#334455" />
          <XAxis dataKey="month" stroke="#00ffff" />
          <YAxis stroke="#00ffff" />
          <Tooltip contentStyle={{ background: "#0a0f2c", border: "1px solid #9b59b6" }} />
          <Area type="monotone" dataKey="cost" stroke="#9b59b6" fill="#9b59b6" fillOpacity={0.4} strokeWidth={4} />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
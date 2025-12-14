"use client";
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";

export function ChurnChart() {
  const data = [
    { month: "Jan", churn: 4.1 },
    { month: "Feb", churn: 3.8 },
    { month: "Mar", churn: 3.5 },
    { month: "Apr", churn: 3.7 },
    { month: "May", churn: 3.4 },
    { month: "Jun", churn: 3.2 },
  ];

  return (
    <div className="bg-cyber-card/60 border-2 border-red-500 rounded-2xl p-8">
      <h2 className="text-3xl font-bold text-red-400 mb-6">Churn Rate Trend</h2>
      <ResponsiveContainer width="100%" height={380}>
        <LineChart data={data}>
          <CartesianGrid stroke="#334455" />
          <XAxis dataKey="month" stroke="#00ffff" />
          <YAxis stroke="#00ffff" domain={[0, 6]} />
          <Tooltip contentStyle={{ background: "#0a0f2c", border: "1px solid #e74c3c" }} />
          <Line type="monotone" dataKey="churn" stroke="#e74c3c" strokeWidth={6} dot={{ fill: "#e74c3c" }} />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
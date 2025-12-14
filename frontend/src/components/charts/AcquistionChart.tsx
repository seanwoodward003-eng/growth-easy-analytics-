"use client";
import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip } from "recharts";

export function AcquisitionChart() {
  const data = [
    { name: "Organic", value: 42, color: "#00ff88" },
    { name: "Paid Social", value: 28, color: "#ff00ff" },
    { name: "Email", value: 18, color: "#00ffff" },
    { name: "Referral", value: 12, color: "#ffff00" },
  ];

  return (
    <div className="bg-cyber-card/60 border border-cyber-neon rounded-2xl p-8">
      <h2 className="text-3xl font-bold text-cyan-400 mb-6">Acquisition Channels</h2>
      <ResponsiveContainer width="100%" height={380}>
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="50%"
            innerRadius={60}
            outerRadius={120}
            paddingAngle={5}
            dataKey="value"
          >
            {data.map((entry, i) => (
              <Cell key={i} fill={entry.color} stroke="#0f1a3d" strokeWidth={3} />
            ))}
          </Pie>
          <Tooltip contentStyle={{ background: "#0a0f2c", border: "1px solid #00ffff" }} />
          <Legend verticalAlign="bottom" height={36} />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}
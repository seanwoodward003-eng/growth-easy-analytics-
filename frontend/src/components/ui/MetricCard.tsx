import { ReactNode } from "react";

type Props = {
  title: string;
  value: string | number;
  trend?: string;
  color?: "cyan" | "red" | "green";
  children?: ReactNode;
};

export function MetricCard({ title, value, trend, color = "cyan", children }: Props) {
  const colors = {
    cyan: "border-cyber-neon text-cyber-neon",
    red: "border-red-500 text-red-400",
    green: "border-green-500 text-green-400",
  };

  return (
    <div className={`bg-cyber-card/80 backdrop-blur border-4 ${colors[color]} rounded-3xl p-10 text-center`}>
      <h3 className="text-2xl mb-4 opacity-80">{title}</h3>
      <p className="text-7xl font-black">{value}</p>
      {trend && <p className="text-2xl mt-4 opacity-80">{trend}</p>}
      {children}
    </div>
  );
}
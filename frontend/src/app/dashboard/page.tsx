// src/app/dashboard/page.tsx
import { RevenueChart } from "@/components/charts/RevenueChart";
import dynamic from "next/dynamic";

// Dynamically load the client-side metrics component (no prerender error)
const DashboardMetrics = dynamic(
  () => import("@/components/DashboardMetrics").then((mod) => mod.DashboardMetrics),
  
);

export default function Dashboard() {
  return (
    <>
      <h1 className="text-5xl font-bold text-cyber-neon mb-10">Dashboard</h1>

      <DashboardMetrics />

      <RevenueChart />
    </>
  );
}
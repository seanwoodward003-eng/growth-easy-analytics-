// src/app/dashboard/revenue/page.tsx
import { RevenueChart } from "@/components/charts/RevenueChart";
import dynamic from "next/dynamic";

// Dynamically load the client-side metrics component (no prerender error)
const RevenueMetrics = dynamic(
  () => import("@/components/RevenueMetrics").then((mod) => mod.RevenueMetrics),

);

export default function RevenuePage() {
  return (
    <>
      <h1 className="text-5xl font-bold text-green-400 mb-10">Revenue</h1>

      <RevenueMetrics />

      <RevenueChart />
    </>
  );
}
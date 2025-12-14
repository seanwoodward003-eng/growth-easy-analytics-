// src/app/dashboard/performance/page.tsx
import { PerformanceChart } from "@/components/charts/PerformanceChart";
import dynamic from "next/dynamic";

// Dynamically load the client-side metrics component (no prerender error)
const PerformanceMetrics = dynamic(
  () => import("@/components/PerformanceMetrics").then((mod) => mod.PerformanceMetrics),
  
);

export default function PerformancePage() {
  return (
    <>
      <h1 className="text-5xl font-bold text-yellow-400 mb-12">Performance</h1>

      <PerformanceMetrics />

      <PerformanceChart />
    </>
  );
}
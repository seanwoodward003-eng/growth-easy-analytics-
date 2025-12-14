// src/app/dashboard/acquisition/page.tsx
import { AcquisitionChart } from "@/components/charts/AcquisitionChart";
import { CostTrendChart } from "@/components/charts/CostTrendChart";
import dynamic from "next/dynamic";

// Dynamically import a client component that uses the hook
const AcquisitionMetrics = dynamic(
  () => import("@/components/AcquisitionMetrics").then((mod) => mod.AcquisitionMetrics),

);

export default function AcquisitionPage() {
  return (
    <>
      <h1 className="text-5xl font-bold text-cyan-400 mb-10">Acquisition</h1>

      <AcquisitionMetrics />

      <div className="grid lg:grid-cols-2 gap-10">
        <AcquisitionChart />
        <CostTrendChart />
      </div>
    </>
  );
}
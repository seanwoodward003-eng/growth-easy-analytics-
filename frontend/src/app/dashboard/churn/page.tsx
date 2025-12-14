// src/app/dashboard/churn/page.tsx
import { ChurnChart } from "@/components/charts/ChurnChart";
import dynamic from "next/dynamic";

// Dynamically load the client-side metrics component
const ChurnMetrics = dynamic(
  () => import("@/components/ChurnMetrics").then((mod) => mod.ChurnMetrics),
  // This prevents prerender error
);

export default function ChurnPage() {
  return (
    <>
      <h1 className="text-7xl font-bold text-red-400 text-center mb-12 glitch" data-text="CHURN RATE">
        CHURN RATE
      </h1>

      <ChurnMetrics />

      <ChurnChart />
    </>
  );
}
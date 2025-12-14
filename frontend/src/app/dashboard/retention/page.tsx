// src/app/dashboard/retention/page.tsx
import { RetentionChart } from "@/components/charts/RetentionChart";
import dynamic from "next/dynamic";

// Dynamically load the client-side metrics component (no prerender error)
const RetentionMetrics = dynamic(
  () => import("@/components/RetentionMetrics").then((mod) => mod.RetentionMetrics),

);

export default function RetentionPage() {
  return (
    <>
      <h1 className="text-5xl font-bold text-purple-400 mb-10">Retention</h1>

      <RetentionMetrics />

      <RetentionChart />
    </>
  );
}
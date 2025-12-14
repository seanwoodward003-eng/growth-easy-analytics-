// src/components/ChurnMetrics.tsx
"use client";

import useMetrics from "@/hooks/useMetrics";

export function ChurnMetrics() {
  const { data } = useMetrics();

  const lost = data.churn.rate ? (data.churn.rate / 100) * 12500 : 400;

  return (
    <>
      <div className="grid md:grid-cols-2 gap-10 max-w-5xl mx-auto mb-12">
        <div className="bg-cyber-card border-2 border-red-500 rounded-2xl p-10 text-center">
          <h3 className="text-3xl mb-4">Churn Rate</h3>
          <p className="text-8xl font-bold text-red-400">
            {data.churn.rate ?? 3.2}%
          </p>
          <p className="text-2xl text-red-300 mt-4">
            = £{lost.toFixed(0)}/mo bleeding
          </p>
        </div>
        <div className="bg-cyber-card border-2 border-yellow-500 rounded-2xl p-10 text-center">
          <h3 className="text-3xl mb-4">At-Risk Customers</h3>
          <p className="text-8xl font-bold text-yellow-400">
            {data.churn.at_risk ?? 18}
          </p>
          <button className="mt-8 bg-red-600 hover:bg-red-500 text-white px-10 py-5 rounded-xl text-xl font-bold">
            Send 15% off win-back
          </button>
        </div>
      </div>

      <div className="bg-cyber-card/60 border-2 border-red-500 rounded-2xl p-8">
        <h3 className="text-3xl text-red-400 mb-6 text-center">AI Insight</h3>
        <p className="text-2xl text-center text-cyan-200">
          {data.ai_insight ?? "18 customers haven’t ordered in 45+ days. A single win-back email could save £2,400/mo."}
        </p>
      </div>
    </>
  );
}
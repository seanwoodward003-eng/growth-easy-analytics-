// src/components/RetentionMetrics.tsx
"use client";

export function RetentionMetrics() {
  return (
    <>
      <div className="grid md:grid-cols-3 gap-8 mb-12">
        <div className="bg-cyber-card border-2 border-purple-500 rounded-2xl p-10 text-center">
          <h3 className="text-2xl">30-Day Retention</h3>
          <p className="text-7xl font-bold text-purple-400">68%</p>
        </div>
        <div className="bg-cyber-card border-2 border-green-500 rounded-2xl p-10 text-center">
          <h3 className="text-2xl">Repeat Purchase Rate</h3>
          <p className="text-7xl font-bold text-green-400">42%</p>
        </div>
        <div className="bg-cyber-card border-2 border-cyan-500 rounded-2xl p-10 text-center">
          <h3 className="text-2xl">Loyal Customers</h3>
          <p className="text-7xl font-bold text-cyber-neon">314</p>
        </div>
      </div>

      <div className="mt-12 bg-purple-900/30 border border-purple-500 rounded-2xl p-10 text-center">
        <h3 className="text-3xl text-purple-300 mb-4">AI Insight</h3>
        <p className="text-2xl">
          Customers who buy 3+ times have 4.2× higher LTV. Launch a loyalty program this quarter.
        </p>
      </div>
    </>
  );
}
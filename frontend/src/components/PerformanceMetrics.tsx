// src/components/PerformanceMetrics.tsx
"use client";

export function PerformanceMetrics() {
  return (
    <div className="grid md:grid-cols-3 gap-10 max-w-5xl mx-auto">
      <div className="bg-cyber-card border-2 border-green-500 rounded-2xl p-12 text-center">
        <h3 className="text-3xl mb-6">Lifetime Value</h3>
        <p className="text-8xl font-bold text-green-400">£162</p>
      </div>
      <div className="bg-cyber-card border-2 border-red-500 rounded-2xl p-12 text-center">
        <h3 className="text-3xl mb-6">Acquisition Cost</h3>
        <p className="text-8xl font-bold text-red-400">£47</p>
      </div>
      <div className="bg-cyber-card border-2 border-cyber-neon rounded-2xl p-12 text-center">
        <h3 className="text-3xl mb-6">LTV:CAC Ratio</h3>
        <p className="text-9xl font-bold text-cyber-neon">3.4:1</p>
        <p className="text-3xl text-green-400 mt-6">Excellent → Keep scaling</p>
      </div>
    </div>
  );
}
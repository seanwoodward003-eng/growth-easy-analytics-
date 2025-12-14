import Link from "next/link";

export function Header() {
  return (
    <header className="sticky top-0 z-50 bg-black/90 backdrop-blur-lg border-b-4 border-cyber-neon">
      <div className="max-w-7xl mx-auto px-6 py-5 flex justify-between items-center">
        <Link href="/dashboard" className="text-4xl font-bold text-cyber-neon">
          GrowthEasy AI
        </Link>
        <Link
          href="/pricing"
          className="bg-gradient-to-r from-purple-600 to-cyan-500 text-white px-8 py-3 rounded-xl font-bold hover:scale-105 transition"
        >
          Upgrade Plan
        </Link>
      </div>
    </header>
  );
}
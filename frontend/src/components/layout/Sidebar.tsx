"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";

const links = [
  { name: "Dashboard", href: "/dashboard" },
  { name: "Churn", href: "/dashboard/churn" },
  { name: "Acquisition", href: "/dashboard/acquisition" },
  { name: "Retention", href: "/dashboard/retention" },
  { name: "Revenue", href: "/dashboard/revenue" },
  { name: "Performance", href: "/dashboard/performance" },
  { name: "Profile", href: "/dashboard/profile" },
];

export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="hidden lg:block w-72 bg-cyber-card/80 backdrop-blur-xl border-r-4 border-cyber-neon min-h-screen p-8">
      <h2 className="text-4xl font-bold text-cyber-neon mb-12">GrowthEasy AI</h2>
      <nav className="space-y-3">
        {links.map((link) => (
          <Link
            key={link.href}
            href={link.href}
            className={`block py-4 px-6 rounded-xl text-xl transition ${
              pathname === link.href
                ? "bg-cyber-neon text-black font-bold shadow-lg shadow-cyan-500/50"
                : "hover:bg-white/10"
            }`}
          >
            {link.name}
          </Link>
        ))}
        <Link
          href="/pricing"
          className="block mt-12 py-4 px-6 rounded-xl text-xl bg-gradient-to-r from-purple-600 to-cyan-500 text-white font-bold text-center hover:scale-105 transition"
        >
          Upgrade to Pro
        </Link>
      </nav>
    </aside>
  );
}
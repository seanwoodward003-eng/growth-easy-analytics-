"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Home, ShoppingCart, Users, DollarSign, TrendingUp, BarChart3, User, Info } from "lucide-react";

const navItems = [
  { name: "Home", href: "/dashboard", icon: Home },
  { name: "Acquisition", href: "/dashboard/acquisition", icon: ShoppingCart },
  { name: "Churn", href: "/dashboard/churn", icon: Users },
  { name: "Retention", href: "/dashboard/retention", icon: Users },
  { name: "Revenue", href: "/dashboard/revenue", icon: DollarSign },
  { name: "Performance", href: "/dashboard/performance", icon: BarChart3 },
  { name: "Profile", href: "/dashboard/profile", icon: User },
  { name: "About", href: "/about", icon: Info },
];

export function MobileNav() {
  const pathname = usePathname();

  return (
    <div className="fixed bottom-0 left-0 right-0 bg-black/90 backdrop-blur-xl border-t-2 border-cyber-neon z-50 md:hidden">
      <div className="grid grid-cols-4 gap-1 p-2">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = pathname.startsWith(item.href);

          return (
            <Link
              key={item.name}
              href={item.href}
              className={`flex flex-col items-center py-2 px-3 rounded-lg transition-all ${
                isActive ? "bg-cyber-neon text-black shadow-lg shadow-cyber-neon/50" : "text-cyan-300 hover:bg-cyber-card"
              }`}
            >
              <Icon className="w-6 h-6" />
              <span className="text-xs mt-1">{item.name}</span>
            </Link>
          );
        })}
      </div>
    </div>
  );
}
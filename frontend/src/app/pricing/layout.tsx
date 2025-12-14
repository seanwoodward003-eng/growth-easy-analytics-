import "./globals.css";
import { Header } from "@/components/layout/Header";
import { MobileNav } from "@/components/layout/MobileNav";

export const metadata = {
  title: "GrowthEasy AI",
  description: "AI Growth Analytics for Shopify",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="font-orbitron min-h-screen bg-gradient-to-br from-cyber-bg to-black">
        <Header />
        {children}
        <MobileNav />
      </body>
    </html>
  );
}
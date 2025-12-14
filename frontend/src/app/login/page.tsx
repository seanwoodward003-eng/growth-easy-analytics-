import Link from "next/link";

export default function LoginPage() {
  return (
    <main className="min-h-screen flex items-center justify-center p-8 bg-gradient-to-br from-cyber-bg via-[#0f1a3d] to-black">
      <div className="text-center max-w-2xl">
        <h1 className="text-8xl font-black text-cyber-neon mb-16 animate-glitch">
          ACCESS THE MATRIX
        </h1>

        <div className="space-y-8">
          <a
            href="https://growth-easy-analytics-2.onrender.com/auth/shopify"
            className="block bg-[#95BF47] text-black py-8 rounded-2xl text-3xl font-bold hover:scale-105 transition shadow-lg shadow-green-500/30"
          >
            Continue with Shopify
          </a>

          <a
            href="https://growth-easy-analytics-2.onrender.com/auth/ga4"
            className="block bg-[#4285F4] text-white py-8 rounded-2xl text-3xl font-bold hover:scale-105 transition shadow-lg shadow-blue-500/30"
          >
            Continue with Google Analytics
          </a>

          <a
            href="https://growth-easy-analytics-2.onrender.com/auth/hubspot"
            className="block bg-[#FF7A59] text-white py-8 rounded-2xl text-3xl font-bold hover:scale-105 transition shadow-lg shadow-orange-500/30"
          >
            Continue with HubSpot
          </a>
        </div>

        <p className="text-cyan-400 text-xl mt-16 opacity-70">
          Your data stays 100% secure • No password needed
        </p>
      </div>
    </main>
  );
}
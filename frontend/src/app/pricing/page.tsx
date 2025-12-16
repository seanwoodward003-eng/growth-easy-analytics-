'use client';

import { useState, useEffect } from 'react';

const EARLY_BIRD_LIMIT = 400;
const TOTAL_LTD_LIMIT = 1000;

export default function Pricing() {
  const [earlyBirdSold, setEarlyBirdSold] = useState(312); // will fetch real later
  const [totalSold, setTotalSold] = useState(712);

  const earlyLeft = EARLY_BIRD_LIMIT - earlyBirdSold;
  const totalLeft = TOTAL_LTD_LIMIT - totalSold;
  const showEarlyBird = earlyBirdSold < EARLY_BIRD_LIMIT;

  const handleCheckout = async (plan: string) => {
    const res = await fetch('/api/create-checkout', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ plan }),
      credentials: 'include',
    });
    const { sessionId } = await res.json();
    const stripe = await loadStripe(process.env.NEXT_PUBLIC_STRIPE_PK!);
    stripe?.redirectToCheckout({ sessionId });
  };

  return (
    <div className="min-h-screen px-6 py-20 text-center">
      <h1 className="glow-title text-6xl md:text-8xl font-black mb-16">
        Upgrade Plan
      </h1>

      <div className="max-w-5xl mx-auto space-y-20">
        {/* Early Bird */}
        {showEarlyBird && (
          <div className="metric-bubble">
            <h2 className="text-5xl md:text-6xl font-bold mb-6">Early Bird Lifetime</h2>
            <p className="text-7xl font-black text-cyan-400 glow-number mb-6">£67</p>
            <p className="text-3xl text-red-400 mb-8">Only {earlyLeft} left!</p>
            <button onClick={() => handleCheckout('lifetime_early')} className="cyber-btn text-3xl px-12 py-6">
              Buy Lifetime £67 (One-time)
            </button>
          </div>
        )}

        {/* Regular Lifetime */}
        {!showEarlyBird && totalSold < TOTAL_LTD_LIMIT && (
          <div className="metric-bubble">
            <h2 className="text-5xl md:text-6xl font-bold mb-6">Lifetime Deal</h2>
            <p className="text-7xl font-black text-cyan-400 glow-number mb-6">£97</p>
            <p className="text-3xl text-red-400 mb-8">Only {totalLeft} lifetime deals left ever</p>
            <button onClick={() => handleCheckout('lifetime')} className="cyber-btn text-3xl px-12 py-6">
              Buy Lifetime £97 (One-time)
            </button>
          </div>
        )}

        {/* Monthly */}
        <div className="metric-bubble">
          <h2 className="text-5xl md:text-6xl font-bold mb-6">Monthly</h2>
          <p className="text-4xl line-through text-gray-500 mb-4">£37/month</p>
          <p className="text-7xl font-black text-cyan-400 glow-number mb-4">£1 <span className="text-4xl">first 7 days</span></p>
          <p className="text-3xl mb-8">Then £37/month</p>
          <button onClick={() => handleCheckout('monthly')} className="cyber-btn text-3xl px-12 py-6">
            Start £1 Trial
          </button>
        </div>

        {/* Annual */}
        <div className="metric-bubble">
          <h2 className="text-5xl md:text-6xl font-bold mb-6">Annual <span className="text-green-400 text-4xl">(Save 33%)</span></h2>
          <p className="text-4xl line-through text-gray-500 mb-4">£444/year</p>
          <p className="text-7xl font-black text-cyan-400 glow-number mb-4">£1 <span className="text-4xl">first 7 days</span></p>
          <p className="text-3xl mb-8">Then £297/year</p>
          <button onClick={() => handleCheckout('annual')} className="cyber-btn text-3xl px-12 py-6">
            Start £1 Trial
          </button>
        </div>
      </div>

      <p className="text-xl text-gray-400 mt-20 max-w-4xl mx-auto">
        Lifetime = current version forever + bug fixes. After we close lifetime deals, you get 12 months of all future features free. After that, upgrade or stay on your version forever.<br /><br />
        Try Monthly or Annual for 7 days at £1 – full access, then auto-billed your selected plan. (card required)
      </p>
    </div>
  );
}
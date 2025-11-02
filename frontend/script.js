// frontend/script.js — FINAL MVP VERSION

document.addEventListener('DOMContentLoaded', () => {

  // === CONFIG ===

  const API_KEY = "8f3a9c2d1e5b7g4h6j9k0l2m3n4p5q6r";

  const USER_ID = "sean";

  const SHOPIFY = {

    api_key: "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",

    password: "cornwall23",

    shop: "0kw39p-2d.myshopify.com"

  };



  // === FETCH DATA ===

  window.fetchData = async (endpoint, extraHeaders = {}) => {

    try {

      const headers = {

        "X-API-Key": API_KEY,

        "user-id": USER_ID,

        ...extraHeaders

      };

      const res = await fetch(`http://localhost:8000/${endpoint}`, { headers });

      if (!res.ok) throw new Error(`HTTP ${res.status}`);

      return await res.json();

    } catch (err) {

      console.error("Fetch error:", err);

      return { error: "Failed to load data" };

    }

  };



  // === FETCH AI INSIGHT ===

  window.fetchAIInsight = async (endpoint) => {

    return window.fetchData("ai/insights", { "endpoint": endpoint });

  };



  // === NAVIGATION ACTIVE STATE ===

  document.querySelectorAll('.nav-btn').forEach(btn => {

    btn.addEventListener('click', () => {

      document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));

      btn.classList.add('active');

    });

  });



  // === REFRESH BUTTON ===

  const refreshBtn = document.querySelector('.refresh-btn');

  if (refreshBtn) {

    refreshBtn.addEventListener('click', () => {

      location.reload();

    });

  }

});


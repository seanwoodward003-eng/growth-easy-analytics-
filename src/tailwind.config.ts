import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      fontFamily: { orbitron: ["var(--font-orbitron)"] },
      colors: {
        cyber: {
          bg: "#0a0f2c",
          card: "#0f1a3d",
          neon: "#00ffff",
          green: "#2ecc71",
          red: "#e74c3c",
          purple: "#9b59b6",
          yellow: "#f1c40f",
        },
      },
      animation: { glitch: "glitch 2s infinite" },
      keyframes: {
        glitch: {
          "0%,100%": { textShadow: "2px 2px #e74c3c, -2px -2px #2ecc71" },
          "50%": { textShadow: "-2px -2px #e74c3c, 2px 2px #2ecc71" },
        },
      },
    },
  },
};

export default config;
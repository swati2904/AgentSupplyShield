import type { Config } from "tailwindcss";

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        shield: {
          ink: "#16201a",
          panel: "#f7faf7",
          line: "#d8e2d7",
          accent: "#267061",
          danger: "#a43f3f",
          warn: "#91651c"
        }
      },
      fontFamily: {
        sans: ["Inter", "ui-sans-serif", "system-ui", "sans-serif"]
      }
    }
  },
  plugins: [],
} satisfies Config;

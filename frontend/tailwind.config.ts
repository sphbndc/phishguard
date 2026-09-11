import type { Config } from "tailwindcss";

const config: Config = {
  darkMode: "class",
  content: ["./app/**/*.{js,ts,jsx,tsx,mdx}", "./components/**/*.{js,ts,jsx,tsx,mdx}"],
  theme: {
    extend: {
      colors: {
        ink: "#10231e",
        forest: "#143e33",
        mint: "#d9f99d",
        paper: "#f4f7f2",
      },
      boxShadow: {
        panel: "0 20px 55px rgba(15, 42, 34, 0.09)",
      },
    },
  },
  plugins: [],
};

export default config;

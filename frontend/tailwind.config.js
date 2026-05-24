/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        bg: "#0b1020",
        panel: "#11172b",
        panel2: "#161d36",
        border: "#1f2a4a",
        accent: "#5eead4",
        muted: "#8b95b2",
      },
    },
  },
  plugins: [],
};

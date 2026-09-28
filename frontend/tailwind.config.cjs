/** @type {import('tailwindcss').Config} */
const v = (name) => `rgb(var(--${name}) / <alpha-value>)`;

module.exports = {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  darkMode: ["class", '[data-theme="dark"]'],
  // tone classes are composed at runtime (text-${tone}, bg-${tone}/10)
  safelist: [{ pattern: /^(text|bg)-(ok|bad|warn|info|accent)(\/10)?$/ }],
  theme: {
    extend: {
      fontFamily: {
        sans: ['"Inter Variable"', "Inter", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ['"JetBrains Mono"', "ui-monospace", "SFMono-Regular", "monospace"],
      },
      colors: {
        bg: v("bg"),
        surface: v("surface"),
        inset: v("inset"),
        line: v("line"),
        "line-strong": v("line-strong"),
        fg: v("fg"),
        muted: v("muted"),
        subtle: v("subtle"),
        accent: v("accent"),
        "accent-fg": v("accent-fg"),
        ok: v("ok"),
        bad: v("bad"),
        warn: v("warn"),
        info: v("info"),
      },
      fontSize: { "2xs": ["0.6875rem", "1rem"] },
      boxShadow: {
        card: "0 1px 2px rgb(16 24 40 / 0.04), 0 1px 3px rgb(16 24 40 / 0.06)",
        pop: "0 12px 32px -8px rgb(16 24 40 / 0.25), 0 4px 8px -4px rgb(16 24 40 / 0.1)",
      },
      keyframes: {
        "fade-in": { from: { opacity: 0 }, to: { opacity: 1 } },
        "slide-in": { from: { transform: "translateX(24px)", opacity: 0 }, to: { transform: "none", opacity: 1 } },
        "rise": { from: { transform: "translateY(6px)", opacity: 0 }, to: { transform: "none", opacity: 1 } },
      },
      animation: {
        "fade-in": "fade-in .15s ease-out",
        "slide-in": "slide-in .2s ease-out",
        rise: "rise .2s ease-out",
      },
    },
  },
  plugins: [],
};

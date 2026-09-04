/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        dark: {
          DEFAULT: '#020617',
          50: '#0b1220',
          100: '#0f172a',
          200: '#172033',
          300: '#1e293b',
          400: '#283b56',
        },
        border: {
          DEFAULT: '#334155',
          subtle: '#233854',
          glow: '#0ea5e9',
        },
        accent: {
          DEFAULT: '#38bdf8',
          hover: '#7dd3fc',
        },
        brand: {
          DEFAULT: '#0ea5e9',
          glow: 'rgba(14, 165, 233, 0.15)',
        },
      },
      fontFamily: {
        mono: ['"Fira Code"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
        sans: ['"Fira Sans"', 'Inter', 'system-ui', '-apple-system', 'sans-serif'],
      },
      boxShadow: {
        glass: '0 8px 32px 0 rgba(0, 0, 0, 0.37)',
        glow: '0 0 20px -3px rgba(14, 165, 233, 0.25)',
        'glow-emerald': '0 0 20px -3px rgba(34, 197, 94, 0.25)',
        'glow-rose': '0 0 20px -3px rgba(239, 68, 68, 0.25)',
      },
    },
  },
  plugins: [],
};

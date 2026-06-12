/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        surface: { DEFAULT: '#0f172a', light: '#1e293b', border: '#334155' },
        accent: { DEFAULT: '#38bdf8', danger: '#ef4444', warn: '#f59e0b', ok: '#22c55e' },
      },
      animation: {
        'fade-in': 'fade-in 0.35s ease-out',
      },
      keyframes: {
        'fade-in': {
          from: { opacity: '0', transform: 'translateY(6px)' },
          to: { opacity: '1', transform: 'translateY(0)' },
        },
      },
    },
  },
  plugins: [],
}
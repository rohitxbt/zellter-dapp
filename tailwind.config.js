/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/**/*.{js,jsx,ts,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        zblack: '#050505',
        zdark: '#0a0a0a',
        zcard: '#121212',
        zwhite: '#ffffff',
        zyellow: '#FFD600',
        zyellowdim: '#CCAA00',
        zgray: '#EAEAEA',
        zborder: '#2A2A2A',
        zsuccess: '#00EDA0',
        zerror: '#FF2E2E'
      },
      fontFamily: {
        sans: ['Space Grotesk', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      },
      animation: {
        'float-slow': 'float 8s ease-in-out infinite',
        'float-fast': 'float 4s ease-in-out infinite',
        'spin-slow': 'spin 12s linear infinite',
        'pulse-glow': 'pulseGlow 4s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'marquee': 'marquee 25s linear infinite',
      },
      keyframes: {
        float: {
          '0%, 100%': { transform: 'translateY(0)' },
          '50%': { transform: 'translateY(-15px)' },
        },
        pulseGlow: {
          '0%, 100%': { opacity: 1, filter: 'drop-shadow(0 0 10px rgba(255, 214, 0, 0.2))' },
          '50%': { opacity: 0.7, filter: 'drop-shadow(0 0 25px rgba(255, 214, 0, 0.6))' }
        },
        marquee: {
          '0%': { transform: 'translateX(0%)' },
          '100%': { transform: 'translateX(-100%)' },
        }
      },
      cursor: {
        'fancy': 'url(data:image/svg+xml;utf8,<svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><circle cx="12" cy="12" r="4" fill="%23FFD600"/></svg>), auto',
      }
    },
  },
  plugins: [],
}
// Property-specific surface aliases keep older light-style primitives and dark-style
// pages on the same dark theme without changing status colors or chart values.
const canvas = '#080c0b';
const panel = '#101714';
const raised = '#18231d';
const text = {
  50: '#f1f7f3',
  100: '#f1f7f3',
  200: '#dce8df',
  300: '#becfc3',
  400: '#a1b5a7',
  500: '#95a99b',
  600: '#a1b5a7',
  700: '#becfc3',
  800: '#dce8df',
  900: '#f1f7f3',
  950: '#f1f7f3',
};
const backgrounds = {
  50: canvas,
  100: raised,
  200: '#1d2c23',
  300: '#2a3d30',
  400: '#49614f',
  500: '#55715e',
  600: '#344c3b',
  700: '#23352a',
  800: raised,
  900: panel,
  950: canvas,
};
const borders = {
  50: '#223328',
  100: '#223328',
  200: '#26392c',
  300: '#344b3b',
  400: '#49614f',
  500: '#55715e',
  600: '#49614f',
  700: '#344b3b',
  800: '#223328',
  900: '#1b2b21',
  950: '#17251c',
};

/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // Emerald actions and mint accents against a charcoal canvas.
        brand: {
          50: '#ecfdf5',
          100: '#d1fae5',
          200: '#a7f3d0',
          300: '#6ee7b7',
          400: '#34d399',
          500: '#10b981',
          600: '#047857',
          700: '#065f46',
          800: '#064e3b',
          900: '#064e3b',
          950: '#022c22',
        },
        accent: {
          50: '#f3fce7',
          100: '#e3f8c5',
          200: '#c9ef9a',
          300: '#afe56f',
          400: '#a3e635',
          500: '#84cc16',
          600: '#65a30d',
          700: '#4d7c0f',
          800: '#3f6212',
          900: '#365314',
          950: '#1a2e05',
        },
        surface: {
          50: '#f1f7f3',
          100: '#e8f1eb',
          200: '#dce8df',
          300: '#becfc3',
          400: '#a1b5a7',
          500: '#758d7d',
          600: '#49614f',
          700: '#23352a',
          800: raised,
          900: panel,
          950: canvas,
        },
        background: 'rgb(var(--background) / <alpha-value>)',
        foreground: 'rgb(var(--foreground) / <alpha-value>)',
        muted: {
          DEFAULT: 'rgb(var(--muted) / <alpha-value>)',
          foreground: 'rgb(var(--muted-foreground) / <alpha-value>)',
        },
      },
      backgroundColor: {
        surface: backgrounds,
        // Existing primitives use bg-white for their card/input surface.
        white: panel,
        gray: { 50: canvas, 100: raised, 200: '#1d2c23', 300: '#2a3d30' },
        brand: { 50: '#0d271c', 100: '#113525' },
        emerald: { 50: '#0d271c', 100: '#113525' },
        green: { 50: '#102719', 100: '#15371f' },
        amber: { 50: '#2c2511', 100: '#382d14' },
        red: { 50: '#2d1719', 100: '#3e2024' },
        blue: { 50: '#14232e', 100: '#1b2e3f' },
        purple: { 50: '#221b31', 100: '#302440' },
      },
      textColor: {
        surface: text,
        gray: text,
        brand: { 600: '#34d399', 700: '#6ee7b7', 800: '#a7f3d0', 900: '#d1fae5' },
        emerald: { 600: '#34d399', 700: '#6ee7b7', 800: '#a7f3d0' },
        green: { 600: '#4ade80', 700: '#86efac', 800: '#bbf7d0' },
        amber: { 600: '#fbbf24', 700: '#fcd34d', 800: '#fde68a' },
        yellow: { 600: '#facc15', 700: '#fde047', 800: '#fef08a' },
        red: { 600: '#f87171', 700: '#fca5a5', 800: '#fecaca' },
        blue: { 600: '#60a5fa', 700: '#93c5fd', 800: '#bfdbfe' },
        purple: { 600: '#c084fc', 700: '#d8b4fe', 800: '#e9d5ff' },
      },
      borderColor: { surface: borders },
      divideColor: { surface: borders },
      fontFamily: {
        sans: ['Inter var', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      },
      fontSize: {
        display: ['32px', { lineHeight: '38px', fontWeight: '600', letterSpacing: '-0.025em' }],
        h1: ['26px', { lineHeight: '32px', fontWeight: '600', letterSpacing: '-0.02em' }],
        h2: ['18px', { lineHeight: '26px', fontWeight: '600', letterSpacing: '-0.012em' }],
        h3: ['15px', { lineHeight: '22px', fontWeight: '600', letterSpacing: '-0.005em' }],
        body: ['14px', { lineHeight: '20px', fontWeight: '400' }],
        small: ['13px', { lineHeight: '18px', fontWeight: '400' }],
      },
      spacing: {
        'row-compact': '0.5rem',
        'row-cozy': '0.75rem',
        'row-comfy': '1rem',
      },
      borderRadius: {
        sm: '0.25rem',
        md: '0.5rem',
        lg: '0.75rem',
        xl: '1rem',
      },
      boxShadow: {
        lift: '0 8px 24px -16px rgb(0 0 0 / 0.8)',
        'lift-hover': '0 12px 28px -16px rgb(0 0 0 / 0.9)',
        'glow-brand': '0 0 0 1px rgb(5 150 105 / 0.4), 0 0 24px -8px rgb(5 150 105 / 0.3)',
        'glow-accent': '0 0 0 1px rgb(163 230 53 / 0.4), 0 0 24px -8px rgb(163 230 53 / 0.2)',
      },
      animation: {
        'fade-in': 'fadeIn 0.3s ease-out',
        'slide-up': 'slideUp 0.3s ease-out',
        'slide-down': 'slideDown 0.3s ease-out',
        'slide-in-right': 'slideInRight 0.2s ease-out',
      },
      keyframes: {
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        slideUp: {
          '0%': { opacity: '0', transform: 'translateY(10px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        slideDown: {
          '0%': { opacity: '0', transform: 'translateY(-10px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        slideInRight: {
          '0%': { opacity: '0', transform: 'translateX(20px)' },
          '100%': { opacity: '1', transform: 'translateX(0)' },
        },
      },
    },
  },
  plugins: [],
};

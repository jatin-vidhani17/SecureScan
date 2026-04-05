/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        slateblue: '#254D70',
        mist: '#EFEFEF',
        ember: '#F4A259',
        pine: '#2A9D8F',
      },
      fontFamily: {
        heading: ['Poppins', 'sans-serif'],
        body: ['Inter', 'Space Grotesk', 'sans-serif'],
      },
      animation: {
        'fadeIn': 'fadeIn 0.6s ease-out both',
      },
    },
  },
  plugins: [],
};

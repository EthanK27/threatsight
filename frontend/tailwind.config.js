/** @type {import('tailwindcss').Config} */
export default {
    content: ["./index.html", "./src/**/*.{js,jsx}"],
    theme: {
        extend: {
            colors: {
                primary: "#202b35",
                accent: "#221d47",
                textMain: "#d6ecf3",
            },
        },
    },
    plugins: [],
};
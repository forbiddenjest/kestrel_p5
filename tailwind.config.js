/** Build-time Tailwind configuration. Node is only required to compile static CSS. */
module.exports = {
  content: ["./app/templates/**/*.html", "./app/static/app.js"],
  theme: { extend: {} },
  plugins: [],
};

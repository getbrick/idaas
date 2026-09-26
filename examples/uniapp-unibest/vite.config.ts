import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";
import uniModule from "@dcloudio/vite-plugin-uni";

const uni = typeof uniModule === "function"
  ? uniModule
  : (uniModule as unknown as { default: typeof uniModule }).default;

export default defineConfig({
  publicDir: "public",
  plugins: [uni()],
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
    },
  },
});

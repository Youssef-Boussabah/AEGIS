import { defineConfig } from "vite";

export default defineConfig({
  server: {
    host: "127.0.0.1",
    strictPort: true,
    proxy: {
      "/healthz": "http://127.0.0.1:8000",
      "/v1": {
        target: "http://127.0.0.1:8000",
        changeOrigin: true,
      },
    },
  },
});

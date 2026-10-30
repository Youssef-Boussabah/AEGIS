import { defineConfig } from "vite";

// `scripts/product.py serve --api-port` passes the API port through AEGIS_API_PORT.
const apiPort = process.env.AEGIS_API_PORT ?? "8000";
if (!/^[0-9]{4,5}$/.test(apiPort) || Number(apiPort) > 65535) throw new Error("AEGIS_API_PORT must be a TCP port number");
const api = `http://127.0.0.1:${apiPort}`;

export default defineConfig({
  server: {
    host: "127.0.0.1",
    strictPort: true,
    proxy: {
      "/healthz": api,
      "/v1": {
        target: api,
        changeOrigin: true,
      },
    },
  },
});

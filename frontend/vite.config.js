import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// base "./" so the built UI also works when Electron loads it from disk
export default defineConfig({
  plugins: [react()],
  base: "./",
  server: { port: 5173, strictPort: true },
});

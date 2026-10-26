import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Dev server proxies the API to the demo backend (C2_Reconnaissance_Detection/demo/server.py).
// For the viva the built dist/ is served by that backend directly; no dev server is needed.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: { '/api': { target: 'http://127.0.0.1:8020', changeOrigin: true } },
  },
});

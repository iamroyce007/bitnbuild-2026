import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

const api = process.env.PHISHGRAPH_API || 'http://localhost:8000';

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    proxy: {
      '/api/v1/events': { target: api.replace(/^http/, 'ws'), ws: true },
      '/api': api,
      '/health': api,
      '/ready': api,
      '/metrics': api,
    },
  },
  build: { outDir: 'dist', chunkSizeWarningLimit: 1500 },
});

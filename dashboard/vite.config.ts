import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    strictPort: true,
    proxy: {
      '/api': {
        target: 'https://localhost:8080',
        secure: false, // Allow self-signed certs in dev
      },
      '/dashboard': {
        target: 'wss://localhost:8080',
        ws: true,
        secure: false,
      },
    }
  }
});

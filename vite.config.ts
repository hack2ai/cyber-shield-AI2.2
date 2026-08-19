import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  base: './',
  plugins: [react(), tailwindcss()],
  build: {
    outDir: 'docs',
    emptyOutDir: true,
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (!id.includes('node_modules')) return undefined;

          if (id.includes('/react/') || id.includes('/react-dom/') || id.includes('/scheduler/')) {
            return 'vendor-react';
          }
          if (id.includes('/firebase/')) {
            return 'vendor-firebase';
          }
          if (id.includes('/recharts/')) {
            return 'vendor-charts';
          }
          if (id.includes('/jspdf/') || id.includes('/html2canvas/')) {
            return 'vendor-documents';
          }
          if (id.includes('/html5-qrcode/') || id.includes('/qrcode/')) {
            return 'vendor-scanning';
          }
          if (id.includes('/motion/') || id.includes('/lucide-react/')) {
            return 'vendor-ui';
          }

          return 'vendor';
        },
      },
    },
  },
  server: {
    port: 3000,
    proxy: {
      '/api': 'http://localhost:3000',
    },
  },
});

import { defineConfig } from 'vite';
import { resolve } from 'path';

export default defineConfig({
  server: {
    proxy: {
      '/backend1': {
        target: '/backend1',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/backend1/, '')
      },
      '/backend2': {
        target: '/backend2',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/backend2/, '')
      }
    }
  },

  build: {
    rollupOptions: {
      input: {
        main: resolve(__dirname, 'index.html'),
        demo: resolve(__dirname, 'demo.html'),
      },
    },
  },
});
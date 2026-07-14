import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:9090',
        // Keep the browser-facing Host/Origin pair intact so development uses
        // the same exact-origin check as the production frontend proxy.
        changeOrigin: false,
      },
    },
  },
})

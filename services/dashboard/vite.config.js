import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// `npm run dev` proxies the API to the XAI service on :7002
const api = { target: 'http://localhost:7002', changeOrigin: true }
export default defineConfig({
  plugins: [react()],
  server: { port: 3000, proxy: { '/api': api, '/login': api, '/logout': api } },
})

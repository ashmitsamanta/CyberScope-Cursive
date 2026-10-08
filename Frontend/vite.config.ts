import { defineConfig } from 'vite';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

export default defineConfig({
  server: {
    port: 5173,
    host: true,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
      }
    }
  },
  build: {
    rollupOptions: {
      input: {
        main: resolve(__dirname, 'index.html'),
        dashboard: resolve(__dirname, 'dashboard.html'),
        cases: resolve(__dirname, 'cases.html'),
        newCase: resolve(__dirname, 'new-case.html'),
        threatMap: resolve(__dirname, 'threat-map.html'),
        fraudGraph: resolve(__dirname, 'fraud-graph.html'),
        entityExplorer: resolve(__dirname, 'entity-explorer.html'),
        transactionExplorer: resolve(__dirname, 'transaction-explorer.html'),
        campaignExplorer: resolve(__dirname, 'campaign-explorer.html'),
        workspace: resolve(__dirname, 'investigation-workspace.html'),
        chatbot: resolve(__dirname, 'chatbot.html'),
        signin: resolve(__dirname, 'signin.html'),
        register: resolve(__dirname, 'register.html'),
      }
    }
  }
});

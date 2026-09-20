import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import path from 'path';
import { defineConfig } from 'vite';

export default defineConfig(() => {
  return {
    plugins: [react(), tailwindcss()],
    resolve: {
      alias: {
        '@': path.resolve(__dirname, '.'),
      },
    },
    server: {
      hmr: process.env.DISABLE_HMR !== 'true',
      watch: process.env.DISABLE_HMR === 'true' ? null : {},
    },
    define: {
      'import.meta.env.VITE_CLERK_PUBLISHABLE_KEY': JSON.stringify(
        process.env.VITE_CLERK_PUBLISHABLE_KEY || 'pk_test_c2F2ZWQtZm93bC0xNjI3LmNsZXJrLmFjY291bnRzLmRldiQ'
      ),
    },
  };
});

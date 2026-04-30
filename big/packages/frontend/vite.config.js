import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'node:path';
var backendTarget = 'http://localhost:3100';
export default defineConfig({
    plugins: [react()],
    resolve: {
        alias: {
            '@': path.resolve(__dirname, './src'),
            '@shared': path.resolve(__dirname, '../shared/src'),
        },
    },
    server: {
        port: 5173,
        proxy: {
            // Proxy API + WebSocket to backend during dev so cookies / CORS are simple.
            '/api': {
                target: backendTarget,
                changeOrigin: true,
            },
            '/ws': {
                target: backendTarget,
                changeOrigin: true,
                ws: true,
            },
        },
    },
    build: {
        outDir: 'dist',
        sourcemap: true,
    },
});

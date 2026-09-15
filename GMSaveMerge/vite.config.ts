import { defineConfig } from 'vite';

export default defineConfig({
    clearScreen: false,
    server: {
        port: 3011,
        strictPort: true,
        watch: {
            ignored: ['**/src-tauri/**'],
        },
    },
});

import { defineConfig } from '@playwright/test';
export default defineConfig({
  testDir: './e2e', timeout: 60_000, workers: 1, reporter: 'list',
  use: { baseURL: 'http://127.0.0.1:5273', launchOptions: { executablePath: process.env.CHROMIUM_PATH ?? undefined } },
  webServer: [
    { command: 'npm run demo -w apps/api', cwd: '../..', env: { PORT: '3100' }, url: 'http://127.0.0.1:3100/healthz', timeout: 90_000, reuseExistingServer: false },
    { command: 'npx vite --port 5273 --host 127.0.0.1', env: { API_URL: 'http://127.0.0.1:3100' }, url: 'http://127.0.0.1:5273', reuseExistingServer: false },
  ],
});

// End-to-end tests in real Chromium, Firefox and WebKit.
//   BASE_URL=http://127.0.0.1:8080 npx playwright test     (against the container, as CI does)
//   npx playwright test                                    (starts scripts/serve.mjs itself)
import { defineConfig, devices } from '@playwright/test';

const baseURL = process.env.BASE_URL ?? 'http://127.0.0.1:4517';

export default defineConfig({
  testDir: './tests',
  timeout: 120_000,
  expect: { timeout: 15_000 },
  fullyParallel: true,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [['github'], ['list']] : 'list',
  use: {
    baseURL,
    acceptDownloads: true,
    trace: 'retain-on-failure',
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    { name: 'firefox', use: { ...devices['Desktop Firefox'] } },
    { name: 'webkit', use: { ...devices['Desktop Safari'] } },
  ],
  webServer: process.env.BASE_URL
    ? undefined
    : { command: 'node ../scripts/serve.mjs --port=4517', url: baseURL, reuseExistingServer: !process.env.CI },
});

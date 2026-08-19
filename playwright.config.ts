import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./browser_tests/",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: "list",
  use: {
    trace: "on-first-retry",
  },
  projects: [
    {
      name: "chromium",
      use: { browserName: "chromium" },
    },
  ],
  webServer: {
    command: "pnpm exec serve . -p 3123",
    port: 3123,
    reuseExistingServer: !process.env.CI,
  },
});

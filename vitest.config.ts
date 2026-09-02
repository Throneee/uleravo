import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    coverage: {
      exclude: ["src/cli.ts", "src/index.ts"],
      include: ["src/**/*.ts"],
      provider: "v8",
      reporter: ["text", "json-summary"],
      thresholds: {
        branches: 75,
        functions: 85,
        lines: 85,
        statements: 85,
      },
    },
    include: ["test/**/*.test.ts"],
    mockReset: true,
    restoreMocks: true,
  },
});

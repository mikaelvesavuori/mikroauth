import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    coverage: {
      enabled: true,
      reportsDirectory: './coverage',
      reporter: ['text', 'lcov'],
      include: ['src/**/*.ts', '!src/index.ts'],
      exclude: [
        'src/infrastructure/adapters',
        'src/interfaces',
        '**/node_modules/**'
      ]
    },
    include: ['tests/**/*.ts']
  }
});

import { defineProject } from 'vitest/config';

export default defineProject({
  test: {
    name: 'advisory-mcp',
    include: ['src/**/*.{test,spec}.ts', 'tests/**/*.{test,spec}.ts'],
    exclude: ['dist/**', 'node_modules/**'],
  },
});

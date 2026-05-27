import { defineProject } from 'vitest/config';

export default defineProject({
  test: {
    name: 'advisory-mcp',
    include: ['tests/**/*.test.ts'],
    environment: 'node',
  },
});

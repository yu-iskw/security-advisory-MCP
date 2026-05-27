import path from 'node:path';
import { fileURLToPath } from 'node:url';

export function getBundledFixturesPath(): string {
  const here = path.dirname(fileURLToPath(import.meta.url));
  return path.resolve(here, '../../tests/fixtures');
}

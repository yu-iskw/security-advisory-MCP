import path from 'node:path';

export function assertSafeArchiveEntry(entryPath: string, destRoot: string): string {
  const root = path.resolve(destRoot);
  const resolved = path.resolve(root, entryPath);
  const relative = path.relative(root, resolved);
  if (relative.startsWith('..') || path.isAbsolute(relative)) {
    throw new Error(`Path traversal rejected: ${entryPath}`);
  }
  return resolved;
}

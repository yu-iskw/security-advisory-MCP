import { realpathSync } from 'node:fs';
import { resolve, sep } from 'node:path';

/**
 * Restrict filesystem reads to a configured set of root directories. Used by
 * scan_sbom_file (M34) before reading user-supplied paths. Each root is
 * canonicalized once (so symlinks at the root point at a stable target), and
 * every candidate path is canonicalized at access time. A path is allowed
 * only if its real path is the root or a descendant of one.
 */

export class PathPolicyError extends Error {
  constructor(
    message: string,
    public readonly reason: 'outside_roots' | 'unresolvable' | 'no_roots',
  ) {
    super(message);
    this.name = 'PathPolicyError';
  }
}

export class PathPolicy {
  private readonly roots: ReadonlyArray<string>;

  constructor(roots: ReadonlyArray<string>) {
    this.roots = roots.map((r) => canonicalize(resolve(r)));
  }

  assertReadable(candidate: string): string {
    if (this.roots.length === 0) {
      throw new PathPolicyError('no allowed root paths configured', 'no_roots');
    }
    const resolved = canonicalize(resolve(candidate));
    for (const root of this.roots) {
      if (resolved === root || resolved.startsWith(root + sep)) {
        return resolved;
      }
    }
    throw new PathPolicyError(
      `path ${candidate} is outside the configured roots`,
      'outside_roots',
    );
  }
}

function canonicalize(p: string): string {
  try {
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- caller-provided path; canonicalized here so the policy check operates on the real target
    return realpathSync(p);
  } catch {
    return p;
  }
}

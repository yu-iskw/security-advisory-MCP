import { appendFileSync, existsSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

/**
 * Append-only audit log. Each call writes one JSON line with a timestamp,
 * the event name, and any user-supplied fields. Files are created lazily;
 * directory creation is best-effort.
 *
 * The auditor never logs whole SBOM payloads, full advisory text, or PII —
 * callers pass only ids / counts / outcomes. See RFC 22.3.
 */

export interface Auditor {
  emit(event: string, fields?: Record<string, unknown>): void;
}

interface FileAuditorOptions {
  path: string;
  now?: () => Date;
}

export class FileAuditor implements Auditor {
  private readonly path: string;
  private readonly now: () => Date;
  private dirReady = false;

  constructor(options: FileAuditorOptions) {
    this.path = options.path;
    this.now = options.now ?? (() => new Date());
  }

  emit(event: string, fields: Record<string, unknown> = {}): void {
    this.ensureDir();
    const line = `${JSON.stringify({ ts: this.now().toISOString(), event, ...fields })}\n`;
    try {
      // eslint-disable-next-line security/detect-non-literal-fs-filename -- audit log path
      appendFileSync(this.path, line, 'utf8');
    } catch {
      // best-effort: never block sync/tool execution on audit-write failure
    }
  }

  private ensureDir(): void {
    if (this.dirReady) return;
    try {
      const dir = dirname(this.path);
      // eslint-disable-next-line security/detect-non-literal-fs-filename -- audit log directory
      if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
      this.dirReady = true;
    } catch {
      this.dirReady = true;
    }
  }
}

/**
 * No-op auditor — used when audit logging is disabled in config or when
 * tests want to suppress writes.
 */
export class NoopAuditor implements Auditor {
  emit(_event: string, _fields?: Record<string, unknown>): void {
    // intentionally empty
  }
}

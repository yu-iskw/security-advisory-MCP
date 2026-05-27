/**
 * Test-only helper: build a minimal ustar tarball in memory from an array
 * of (path, content) pairs. Used by ingest/tar.test.ts and the Vulnrichment
 * integration fixture so we don't have to check binary tarballs into the
 * repository.
 */

interface TarEntryInput {
  path: string;
  content: Uint8Array;
}

const BLOCK = 512;

function writeString(buf: Uint8Array, off: number, value: string, max: number): void {
  const bytes = new TextEncoder().encode(value);
  buf.set(bytes.subarray(0, Math.min(bytes.length, max)), off);
}

function writeOctal(buf: Uint8Array, off: number, value: number, width: number): void {
  const s = value.toString(8).padStart(width - 1, '0');
  writeString(buf, off, s, width - 1);
}

function buildHeader(path: string, size: number): Uint8Array {
  const header = new Uint8Array(BLOCK);
  // ustar supports name<=100 + optional prefix<=155. For simplicity, require
  // path <= 100 chars in test fixtures.
  if (path.length > 100) {
    throw new Error(`tar-builder fixture path too long: ${path}`);
  }
  writeString(header, 0, path, 100);
  writeOctal(header, 100, 0o644, 8); // mode
  writeOctal(header, 108, 0, 8); // uid
  writeOctal(header, 116, 0, 8); // gid
  writeOctal(header, 124, size, 12); // size
  writeOctal(header, 136, 0, 12); // mtime
  // chksum: 8 spaces during computation
  header.fill(0x20, 148, 148 + 8);
  header[156] = '0'.charCodeAt(0); // typeflag regular file
  writeString(header, 257, 'ustar', 6);
  header[263] = '0'.charCodeAt(0);
  header[264] = '0'.charCodeAt(0);
  let sum = 0;
  for (const b of header) sum += b;
  const chksum = sum.toString(8).padStart(6, '0');
  writeString(header, 148, chksum, 6);
  header[154] = 0;
  header[155] = 0x20;
  return header;
}

export function buildTar(entries: TarEntryInput[]): Uint8Array {
  const chunks: Uint8Array[] = [];
  for (const entry of entries) {
    chunks.push(buildHeader(entry.path, entry.content.length));
    chunks.push(entry.content);
    const pad = (BLOCK - (entry.content.length % BLOCK)) % BLOCK;
    if (pad > 0) chunks.push(new Uint8Array(pad));
  }
  chunks.push(new Uint8Array(BLOCK));
  chunks.push(new Uint8Array(BLOCK));
  const total = chunks.reduce((a, c) => a + c.length, 0);
  const out = new Uint8Array(total);
  let pos = 0;
  for (const c of chunks) {
    out.set(c, pos);
    pos += c.length;
  }
  return out;
}

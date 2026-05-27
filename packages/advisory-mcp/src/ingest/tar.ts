import { LIMITS } from '../security/limits.js';

import { assertEntryCount, DecompressionError, sanitizeArchivePath } from './decompressor.js';

export interface TarEntry {
  path: string;
  size: number;
  content: Uint8Array;
}

interface ReadTarOptions {
  maxBytes?: number;
}

interface TarHeader {
  name: string;
  prefix: string;
  size: number;
  typeflag: string;
  typeflagCode: number;
}

/**
 * Minimal in-memory tar reader. Handles:
 *  - ustar header layout (full path = prefix/'/'/name, size as octal);
 *  - typeflag '0' and the legacy '\0' (regular file);
 *  - GNU 'L' long-name extension (the data block is the next entry's path);
 *  - pax 'x' extended header with a leading `<len> path=...\n` record.
 *
 * Each emitted entry's path is sanitized via sanitizeArchivePath, so absolute
 * paths / parent traversal / drive prefixes are rejected. Total decompressed
 * size and entry count are capped per LIMITS / DecompressionError.
 *
 * Non-file entries (directories, symlinks, etc.) are skipped silently.
 */
export function readTar(bytes: Uint8Array, options: ReadTarOptions = {}): TarEntry[] {
  const maxBytes = options.maxBytes ?? LIMITS.defaultMaxDecompressedBytes;
  const state = { entries: [] as TarEntry[], pendingPath: null as string | null, totalContent: 0 };
  let offset = 0;

  while (offset + 512 <= bytes.length) {
    const headerBlock = bytes.subarray(offset, offset + 512);
    if (isAllZero(headerBlock)) break;
    offset += 512;

    const header = parseHeader(headerBlock);
    const blocks = Math.ceil(header.size / 512);
    const dataEnd = offset + blocks * 512;
    if (dataEnd > bytes.length) {
      throw new DecompressionError('truncated tar entry', 'invalid_archive');
    }

    const data = bytes.subarray(offset, offset + header.size);
    handleEntry(header, data, state, maxBytes);
    offset = dataEnd;
  }
  return state.entries;
}

function parseHeader(block: Uint8Array): TarHeader {
  const name = readCString(block, 0, 100);
  const prefix = readCString(block, 345, 155);
  const sizeStr = readCString(block, 124, 12);
  const typeflagCode = block[156] ?? 0;
  const typeflag = String.fromCharCode(typeflagCode);
  const size = parseOctal(sizeStr);
  if (size < 0) {
    throw new DecompressionError(`invalid tar entry size: ${sizeStr}`, 'invalid_archive');
  }
  return { name, prefix, size, typeflag, typeflagCode };
}

interface TarReaderState {
  entries: TarEntry[];
  pendingPath: string | null;
  totalContent: number;
}

function handleEntry(
  header: TarHeader,
  data: Uint8Array,
  state: TarReaderState,
  maxBytes: number,
): void {
  if (header.typeflag === 'L') {
    state.pendingPath = decode(data).replace(/\0+$/, '');
    return;
  }
  if (header.typeflag === 'x') {
    const match = /^\d+ path=(.+)\n/m.exec(decode(data));
    if (match?.[1] !== undefined) state.pendingPath = match[1];
    return;
  }
  const isRegular = header.typeflag === '0' || header.typeflagCode === 0;
  if (!isRegular) return;

  const rawPath = state.pendingPath ?? joinPath(header.prefix, header.name);
  state.pendingPath = null;
  if (rawPath === '') return;

  const sanitized = sanitizeArchivePath(rawPath);
  state.totalContent += header.size;
  if (state.totalContent > maxBytes) {
    throw new DecompressionError(`tar contents exceed limit ${maxBytes}`, 'oversized');
  }
  state.entries.push({ path: sanitized, size: header.size, content: new Uint8Array(data) });
  assertEntryCount(state.entries.length);
}

function joinPath(prefix: string, name: string): string {
  return prefix === '' ? name : `${prefix}/${name}`;
}

function isAllZero(buf: Uint8Array): boolean {
  for (const b of buf) if (b !== 0) return false;
  return true;
}

function readCString(buf: Uint8Array, off: number, len: number): string {
  let end = off;
  const limit = off + len;
  // `end` is a bounded counter, not an external index.
  // eslint-disable-next-line security/detect-object-injection
  while (end < limit && buf[end] !== 0) end++;
  return decode(buf.subarray(off, end));
}

function parseOctal(input: string): number {
  const trimmed = input.replace(/[\s\0]/g, '');
  if (trimmed === '') return 0;
  const n = Number.parseInt(trimmed, 8);
  return Number.isFinite(n) ? n : -1;
}

function decode(buf: Uint8Array): string {
  return new TextDecoder('utf-8', { fatal: false }).decode(buf);
}

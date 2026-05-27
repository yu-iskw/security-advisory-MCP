function rowRecord(row: unknown): Record<string, unknown> {
  if (typeof row !== 'object' || row === null) {
    throw new Error('Expected SQLite row object');
  }
  return row as Record<string, unknown>;
}

export function readStringColumn(row: unknown, key: string): string {
  const record = rowRecord(row);
  if (!Object.hasOwn(record, key)) {
    throw new Error(`Expected row with string column ${key}`);
  }
  const value = record[key];
  if (typeof value !== 'string') {
    throw new Error(`Expected string for ${key}`);
  }
  return value;
}

export function readNumberColumn(row: unknown, key: string): number {
  const record = rowRecord(row);
  if (!Object.hasOwn(record, key)) {
    throw new Error(`Expected row with number column ${key}`);
  }
  const value = record[key];
  if (typeof value !== 'number') {
    throw new Error(`Expected number for ${key}`);
  }
  return value;
}

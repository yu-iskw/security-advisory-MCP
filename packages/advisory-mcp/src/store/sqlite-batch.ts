/** Stay below SQLite's default SQLITE_MAX_VARIABLE_NUMBER (999). */
export const SQLITE_IN_CHUNK_SIZE = 400;

export function chunkArray<T>(items: T[], chunkSize: number): T[][] {
  const chunks: T[][] = [];
  for (let i = 0; i < items.length; i += chunkSize) {
    chunks.push(items.slice(i, i + chunkSize));
  }
  return chunks;
}

/**
 * Hard size limits applied to all ingest paths. Defaults align with RFC 19.3;
 * runtime values come from `config.maxDownloadBytes` / `maxDecompressedBytes`.
 */
export const LIMITS = {
  /** Cap for a single HTTP response body when downloading a source artifact. */
  defaultMaxDownloadBytes: 1_000_000_000,
  /** Cap for the post-decompression size of an archive. Bomb defense. */
  defaultMaxDecompressedBytes: 5_000_000_000,
  /** Max number of entries permitted inside a single archive (tar/zip). */
  maxArchiveEntries: 200_000,
  /** Max bytes for a single advisory record's textual fields (after concat). */
  maxAdvisoryTextBytes: 1_000_000,
  /** Max length of an individual sanitized text field returned to the client. */
  maxClientTextChars: 64_000,
  /** Max bytes for an inline SBOM JSON input to scan_sbom. RFC 11.1. */
  maxSbomJsonBytes: 20_000_000,
  /** HTTP request timeout in milliseconds. */
  httpTimeoutMs: 60_000,
} as const;

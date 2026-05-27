import fs from 'node:fs';
import path from 'node:path';

import { hashPayload, type NormalizedRecord } from '../ingest/merger.js';

import { evidenceTypeForSource } from './evidence-type.js';

import type { Advisory } from '../schemas/advisory.js';
import type { Evidence, TrustTier } from '../schemas/evidence.js';
import type { SourceId } from '../schemas/source.js';

const UTF8_ENCODING = 'utf8' as const;

export type FixtureAdapter = (options: {
  dir: string;
  sourceId: SourceId;
  trustTier: TrustTier;
  fetchedAt: string;
}) => NormalizedRecord[];

function readIdField(value: unknown): string {
  if (typeof value === 'string') {
    return value;
  }
  if (typeof value === 'number') {
    return String(value);
  }
  return '';
}

function parseFixtureJson(
  sourceId: SourceId,
  trustTier: TrustTier,
  json: Record<string, unknown>,
  fetchedAt: string,
  filePath: string,
): NormalizedRecord[] {
  if (Array.isArray(json.records)) {
    return (json.records as Record<string, unknown>[]).flatMap((r) =>
      parseFixtureJson(sourceId, trustTier, r, fetchedAt, filePath),
    );
  }

  const advisoryId = readIdField(json.advisoryId) || readIdField(json.id) || readIdField(json.cve);
  if (!advisoryId) {
    return [];
  }

  const advisory: Partial<Advisory> = {
    title: json.title as string | undefined,
    description: json.description as string | undefined,
    publishedAt: json.publishedAt as string | undefined,
    modifiedAt: json.modifiedAt as string | undefined,
    affected: Array.isArray(json.affected) ? (json.affected as Advisory['affected']) : [],
    cwes: Array.isArray(json.cwes) ? (json.cwes as string[]) : [],
    cvss: Array.isArray(json.cvss) ? (json.cvss as Advisory['cvss']) : [],
    epss: json.epss as Advisory['epss'],
    kev: json.kev as Advisory['kev'],
    ssvc: json.ssvc as Advisory['ssvc'],
    references: Array.isArray(json.references) ? (json.references as Advisory['references']) : [],
  };

  const evidence: Evidence = {
    id: `${sourceId}:${advisoryId}:${hashPayload(filePath).slice(0, 12)}`,
    advisoryId,
    source: sourceId,
    sourceRecordId: filePath,
    type: evidenceTypeForSource(sourceId),
    fetchedAt,
    confidence: 0.9,
    trustTier,
    summary: `${sourceId} record for ${advisoryId}`,
    normalizedJson: json,
    rawRef: hashPayload(filePath),
  };

  return [
    {
      advisoryId,
      aliases: Array.isArray(json.aliases) ? (json.aliases as string[]) : [],
      advisory,
      evidence,
    },
  ];
}

function loadJsonFiles(options: {
  dir: string;
  sourceId: SourceId;
  trustTier: TrustTier;
  fetchedAt: string;
}): NormalizedRecord[] {
  const files = fs.readdirSync(options.dir).filter((f) => f.endsWith('.json'));
  const records: NormalizedRecord[] = [];
  for (const file of files) {
    const full = path.join(options.dir, file);
    const json = JSON.parse(fs.readFileSync(full, UTF8_ENCODING)) as Record<string, unknown>;
    records.push(
      ...parseFixtureJson(options.sourceId, options.trustTier, json, options.fetchedAt, full),
    );
  }
  return records;
}

function loadEpssCsv(options: {
  dir: string;
  sourceId: SourceId;
  trustTier: TrustTier;
  fetchedAt: string;
}): NormalizedRecord[] {
  const files = fs.readdirSync(options.dir).filter((f) => f.endsWith('.csv'));
  const out: NormalizedRecord[] = [];
  for (const file of files) {
    const full = path.join(options.dir, file);
    const csv = fs.readFileSync(full, UTF8_ENCODING);
    const lines = csv.trim().split('\n').slice(1);
    for (const line of lines) {
      const [cve, epss, percentile] = line.split(',');
      if (!cve.startsWith('CVE-')) {
        continue;
      }
      out.push({
        advisoryId: cve,
        aliases: [],
        advisory: {
          epss: {
            cve,
            epss: Number(epss),
            percentile: Number(percentile),
            date: options.fetchedAt.slice(0, 10),
          },
        },
        evidence: {
          id: `first-epss:${cve}`,
          advisoryId: cve,
          source: 'first-epss',
          type: 'epss',
          fetchedAt: options.fetchedAt,
          confidence: 0.85,
          trustTier: options.trustTier,
          summary: `EPSS ${epss} (${percentile} percentile)`,
          normalizedJson: { cve, epss, percentile },
          rawRef: hashPayload(full),
        },
      });
    }
  }
  return out;
}

function loadKevJson(options: {
  dir: string;
  sourceId: SourceId;
  trustTier: TrustTier;
  fetchedAt: string;
}): NormalizedRecord[] {
  const files = fs.readdirSync(options.dir).filter((f) => f.endsWith('.json'));
  const out: NormalizedRecord[] = [];
  for (const file of files) {
    const full = path.join(options.dir, file);
    const json = JSON.parse(fs.readFileSync(full, UTF8_ENCODING)) as unknown;
    const data = json as { vulnerabilities?: Array<{ cveID: string; dateAdded?: string }> };
    for (const v of data.vulnerabilities ?? []) {
      out.push({
        advisoryId: v.cveID,
        aliases: [],
        advisory: { kev: { cve: v.cveID, dateAdded: v.dateAdded } },
        evidence: {
          id: `cisa-kev:${v.cveID}`,
          advisoryId: v.cveID,
          source: 'cisa-kev',
          type: 'kev',
          fetchedAt: options.fetchedAt,
          confidence: 0.95,
          trustTier: options.trustTier,
          summary: `CISA KEV entry ${v.cveID}`,
          normalizedJson: v,
          rawRef: hashPayload(full),
        },
      });
    }
  }
  return out;
}

export const FIXTURE_ADAPTERS: Record<SourceId, FixtureAdapter> = {
  cveproject: loadJsonFiles,
  'nvd-feed': loadJsonFiles,
  'cisa-kev': loadKevJson,
  'cisa-vulnrichment': loadJsonFiles,
  'first-epss': loadEpssCsv,
  osv: loadJsonFiles,
  'github-advisory': loadJsonFiles,
  'ossf-malicious-packages': loadJsonFiles,
  debian: loadJsonFiles,
  ubuntu: loadJsonFiles,
  alpine: loadJsonFiles,
  rustsec: loadJsonFiles,
  'go-vulndb': loadJsonFiles,
  pypa: loadJsonFiles,
  'mitre-cwe': loadJsonFiles,
  'mitre-capec': loadJsonFiles,
};

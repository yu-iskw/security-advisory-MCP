import fs from 'node:fs';
import path from 'node:path';

import { hashPayload, type NormalizedRecord } from '../ingest/merger.js';

import type { SourceDefinition } from './source.js';
import type { Advisory } from '../schemas/advisory.js';
import type { Evidence, TrustTier } from '../schemas/evidence.js';
import type { SourceId } from '../schemas/source.js';

const UTF8_ENCODING = 'utf8' as const;
const SOURCE_ID_FIRST_EPSS = 'first-epss' as const satisfies SourceId;

export function loadFixtureRecords(
  fixtureRoot: string,
  source: SourceDefinition,
): NormalizedRecord[] {
  const dir = path.join(fixtureRoot, source.fixtureSubdir);
  if (!fs.existsSync(dir)) {
    return [];
  }
  const files = fs.readdirSync(dir).filter((f) => f.endsWith('.json') || f.endsWith('.csv'));
  const records: NormalizedRecord[] = [];
  const fetchedAt = new Date().toISOString();

  for (const file of files) {
    const full = path.join(dir, file);
    const raw = fs.readFileSync(full);
    if (source.id === SOURCE_ID_FIRST_EPSS) {
      records.push(...parseEpssCsv(raw.toString(UTF8_ENCODING), fetchedAt, full));
      continue;
    }
    if (source.id === 'cisa-kev') {
      records.push(
        ...parseKevJson(JSON.parse(raw.toString(UTF8_ENCODING)) as unknown, fetchedAt, full),
      );
      continue;
    }
    const json = JSON.parse(raw.toString(UTF8_ENCODING)) as Record<string, unknown>;
    records.push(...parseFixtureJson(source.id, source.trustTier, json, fetchedAt, full));
  }
  return records;
}

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
    type: mapEvidenceType(sourceId),
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

function mapEvidenceType(sourceId: SourceId): Evidence['type'] {
  switch (sourceId) {
    case 'cveproject':
      return 'cve_record';
    case 'nvd-feed':
      return 'nvd_enrichment';
    case 'cisa-kev':
      return 'kev';
    case SOURCE_ID_FIRST_EPSS:
      return 'epss';
    case 'cisa-vulnrichment':
      return 'vulnrichment';
    case 'osv':
      return 'osv';
    case 'github-advisory':
      return 'ghsa';
    case 'ossf-malicious-packages':
      return 'malicious_package';
    case 'debian':
    case 'ubuntu':
    case 'alpine':
      return 'distro';
    case 'rustsec':
    case 'go-vulndb':
    case 'pypa':
      return 'osv';
    case 'mitre-cwe':
    case 'mitre-capec':
      return 'taxonomy';
    default:
      return 'cve_record';
  }
}

function parseEpssCsv(csv: string, fetchedAt: string, filePath: string): NormalizedRecord[] {
  const lines = csv.trim().split('\n').slice(1);
  const out: NormalizedRecord[] = [];
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
          date: fetchedAt.slice(0, 10),
        },
      },
      evidence: {
        id: `first-epss:${cve}`,
        advisoryId: cve,
        source: 'first-epss',
        type: 'epss',
        fetchedAt,
        confidence: 0.85,
        trustTier: 'A',
        summary: `EPSS ${epss} (${percentile} percentile)`,
        normalizedJson: { cve, epss, percentile },
        rawRef: hashPayload(filePath),
      },
    });
  }
  return out;
}

function parseKevJson(json: unknown, fetchedAt: string, filePath: string): NormalizedRecord[] {
  const data = json as { vulnerabilities?: Array<{ cveID: string; dateAdded?: string }> };
  const list = data.vulnerabilities ?? [];
  return list.map((v) => ({
    advisoryId: v.cveID,
    aliases: [],
    advisory: {
      kev: { cve: v.cveID, dateAdded: v.dateAdded },
    },
    evidence: {
      id: `cisa-kev:${v.cveID}`,
      advisoryId: v.cveID,
      source: 'cisa-kev',
      type: 'kev',
      fetchedAt,
      confidence: 0.95,
      trustTier: 'A',
      summary: `CISA KEV entry ${v.cveID}`,
      normalizedJson: v,
      rawRef: hashPayload(filePath),
    },
  }));
}

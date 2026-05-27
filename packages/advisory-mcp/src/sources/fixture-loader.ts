import fs from 'node:fs';
import path from 'node:path';

import type { Advisory } from '../schemas/advisory.js';
import type { Evidence } from '../schemas/evidence.js';
import type { TrustTier } from '../schemas/evidence.js';
import { hashPayload, type NormalizedRecord } from '../ingest/merger.js';
import type { SourceDefinition } from './source.js';
import type { SourceId } from '../schemas/source.js';

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
    if (source.id === 'first-epss') {
      records.push(...parseEpssCsv(raw.toString('utf8'), fetchedAt, full));
      continue;
    }
    if (source.id === 'cisa-kev') {
      records.push(...parseKevJson(JSON.parse(raw.toString('utf8')) as unknown, fetchedAt, full));
      continue;
    }
    const json = JSON.parse(raw.toString('utf8')) as Record<string, unknown>;
    records.push(...parseFixtureJson(source.id, source.trustTier, json, fetchedAt, full));
  }
  return records;
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

  const advisoryId = String(json.advisoryId ?? json.id ?? json.cve ?? '');
  if (!advisoryId) {
    return [];
  }

  const advisory: Partial<Advisory> = {
    title: json.title as string | undefined,
    description: json.description as string | undefined,
    publishedAt: json.publishedAt as string | undefined,
    modifiedAt: json.modifiedAt as string | undefined,
    affected: (json.affected as Advisory['affected']) ?? [],
    cwes: (json.cwes as string[]) ?? [],
    cvss: (json.cvss as Advisory['cvss']) ?? [],
    epss: json.epss as Advisory['epss'],
    kev: json.kev as Advisory['kev'],
    ssvc: json.ssvc as Advisory['ssvc'],
    references: (json.references as Advisory['references']) ?? [],
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
      aliases: (json.aliases as string[]) ?? [],
      advisory,
      evidence,
    },
  ];
}

function mapEvidenceType(sourceId: SourceId): Evidence['type'] {
  const map: Partial<Record<SourceId, Evidence['type']>> = {
    cveproject: 'cve_record',
    'nvd-feed': 'nvd_enrichment',
    'cisa-kev': 'kev',
    'first-epss': 'epss',
    'cisa-vulnrichment': 'vulnrichment',
    osv: 'osv',
    'github-advisory': 'ghsa',
    'ossf-malicious-packages': 'malicious_package',
    debian: 'distro',
    ubuntu: 'distro',
    alpine: 'distro',
    rustsec: 'osv',
    'go-vulndb': 'osv',
    pypa: 'osv',
    'mitre-cwe': 'taxonomy',
    'mitre-capec': 'taxonomy',
  };
  return map[sourceId] ?? 'cve_record';
}

function parseEpssCsv(csv: string, fetchedAt: string, filePath: string): NormalizedRecord[] {
  const lines = csv.trim().split('\n').slice(1);
  const out: NormalizedRecord[] = [];
  for (const line of lines) {
    const [cve, epss, percentile] = line.split(',');
    if (!cve?.startsWith('CVE-')) {
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

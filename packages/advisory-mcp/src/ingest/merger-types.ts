export interface EvidenceRowForMerge {
  source: string;
  evidenceType: string;
  normalizedJson: string;
  title?: string;
  description?: string;
  publishedAt?: string | null;
  modifiedAt?: string | null;
}

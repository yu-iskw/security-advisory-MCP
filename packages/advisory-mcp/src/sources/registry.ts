import type { SourceAdapter, SyncPreset } from './source.js';

const PRESET_GROUPS: Record<SyncPreset, ReadonlyArray<SyncPreset>> = {
  core: ['core'],
  packages: ['packages'],
  ecosystems: ['ecosystems'],
  context: ['context'],
  research: ['research'],
};

const ALL_PRESET: ReadonlyArray<SyncPreset> = [
  'core',
  'packages',
  'ecosystems',
  'context',
];

export class SourceRegistry {
  private readonly adapters = new Map<string, SourceAdapter>();

  register(adapter: SourceAdapter): void {
    if (this.adapters.has(adapter.id)) {
      throw new Error(`source already registered: ${adapter.id}`);
    }
    this.adapters.set(adapter.id, adapter);
  }

  get(id: string): SourceAdapter | undefined {
    return this.adapters.get(id);
  }

  listAll(): SourceAdapter[] {
    return [...this.adapters.values()].sort((a, b) => a.id.localeCompare(b.id));
  }

  /**
   * Resolve adapters for a preset name. `all` expands to every non-research
   * preset; `research` is always opt-in and never included by `all`.
   */
  resolvePreset(name: SyncPreset | 'all'): SourceAdapter[] {
    // `name` is a constrained union member; lookup is safe.
    // eslint-disable-next-line security/detect-object-injection
    const targets = name === 'all' ? ALL_PRESET : PRESET_GROUPS[name];
    return this.listAll().filter((a) => targets.includes(a.defaultPreset));
  }
}

import { access, mkdir, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';

import { defaultConfig } from '../../config/config.js';
import { defaultPaths } from '../../util/paths.js';

export interface InitOptions {
  config?: string;
  force?: boolean;
}

export async function runInit(options: InitOptions): Promise<void> {
  const paths = defaultPaths();
  const configPath = options.config ?? paths.configPath;

  // eslint-disable-next-line security/detect-non-literal-fs-filename -- documented config dir
  await mkdir(dirname(configPath), { recursive: true });
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  await mkdir(paths.cachePath, { recursive: true });
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  await mkdir(dirname(paths.databasePath), { recursive: true });

  let already = false;
  try {
    await access(configPath);
    already = true;
  } catch {
    // file does not exist; proceed to write
  }

  if (already && options.force !== true) {
    process.stdout.write(
      `Config already exists at ${configPath}. Re-run with --force to overwrite.\n`,
    );
    return;
  }

  const cfg = defaultConfig();
  // eslint-disable-next-line security/detect-non-literal-fs-filename -- documented config path
  await writeFile(configPath, `${JSON.stringify(cfg, null, 2)}\n`, 'utf8');
  process.stdout.write(
    `Initialized advisory-mcp:\n` +
      `  config:   ${configPath}\n` +
      `  database: ${paths.databasePath}\n` +
      `  cache:    ${paths.cachePath}\n` +
      `Next: run \`advisory-mcp sync --preset core\`.\n`,
  );
}

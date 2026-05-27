interface PingResult {
  ok: true;
  name: string;
  version: string;
}

export function ping(name: string, version: string): PingResult {
  return { ok: true, name, version };
}

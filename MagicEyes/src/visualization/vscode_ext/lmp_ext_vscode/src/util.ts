let userAgent: string;
let version: string;

export function setVersion(v: string) {
  version = v;
  userAgent = `Grafana VSCode Extension/v${version}`;
}

export function getVersion(): string {
  return version;
}

export function getUserAgent(): string {
  return userAgent;
}
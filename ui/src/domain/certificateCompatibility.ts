export interface CertificateCompatibilityProfile {
  version: string;
  status: "trusted" | "not_trusted" | "unknown" | "invalid";
  reason: string;
  roots: { fingerprint: string; name: string }[];
}

export interface CertificateCompatibilityResult {
  status: "compatible" | "not_trusted" | "unknown" | "invalid";
  reason: string;
  estimated: true;
  minimumVersion?: string;
  supportedVersions: string[];
  profiles: CertificateCompatibilityProfile[];
  dataVersion: string;
  evaluatedAt: string;
  scope: "android_system_roots";
  oldestVersion?: string;
  newestVersion?: string;
}

export type CertificateCompatibilityState =
  { phase: "idle" | "deferred" | "loading" | "unavailable" } | { phase: "ready"; result: CertificateCompatibilityResult };

import type { CertificateCompatibilityResult, CertificateCompatibilityState } from "../domain/certificateCompatibility.ts";

type Translate = (key: string, options?: Record<string, unknown>) => string;

export function chunkCertificateIds(ids: string[]): string[][] {
  const unique = [...new Set(ids.filter(Boolean))];
  const chunks: string[][] = [];
  for (let i = 0; i < unique.length; i += 100) chunks.push(unique.slice(i, i + 100));
  return chunks;
}

// One gate per hook instance; changing input or cleanup invalidates every older response.
export function createLatestRequestGate() {
  let sequence = 0;
  return {
    next: () => ++sequence,
    isCurrent: (request: number) => request === sequence,
    invalidate: () => ++sequence,
  };
}

export function compatibilitySummary(result: CertificateCompatibilityResult, t: Translate): string {
  const profiles = result.profiles;
  const ranges: string[] = [];
  let start = -1;
  for (let i = 0; i <= profiles.length; i++) {
    if (profiles[i]?.status === "trusted") {
      if (start < 0) start = i;
    } else if (start >= 0) {
      ranges.push(start === i - 1 ? profiles[start].version : `${profiles[start].version}–${profiles[i - 1].version}`);
      start = -1;
    }
  }
  const trusted = profiles.filter((profile) => profile.status === "trusted");
  // Only a single contiguous suffix can be described by a minimum version.
  if (ranges.length === 1 && profiles.at(-1)?.status === "trusted") {
    return t("certificate.compatibility.summary.minimum", { version: trusted[0].version });
  }
  if (ranges.length > 0) return t("certificate.compatibility.summary.ranges", { versions: ranges.join(", ") });
  return t(`certificate.compatibility.summary.${result.status}`, { defaultValue: t("certificate.compatibility.summary.unknown") });
}

export function compatibilityStateText(state: CertificateCompatibilityState, t: Translate): string {
  if (state.phase === "ready") return compatibilitySummary(state.result, t);
  return t(`certificate.compatibility.${state.phase}`);
}

export function compatibilityReason(reason: string, t: Translate): string {
  return t(`certificate.compatibility.reason.${reason}`, { defaultValue: t("certificate.compatibility.reason.other") });
}

export function previewIdentity(source: string | undefined, certificate: string | undefined): string {
  return JSON.stringify([source || "form", certificate?.trim() || ""]);
}

export function initialPreviewState(source: string | undefined, certificate: string | undefined): CertificateCompatibilityState {
  if (source && source !== "form") return { phase: "deferred" };
  return { phase: certificate?.trim() ? "loading" : "idle" };
}

export function currentCompatibilityState(
  stored: { key: string; state: CertificateCompatibilityState },
  key: string,
  initial: CertificateCompatibilityState
): CertificateCompatibilityState {
  return stored.key === key ? stored.state : initial;
}

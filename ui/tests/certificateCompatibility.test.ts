import assert from "node:assert/strict";
import test from "node:test";

import type { CertificateCompatibilityResult } from "../src/domain/certificateCompatibility.ts";
import {
  chunkCertificateIds,
  compatibilityReason,
  compatibilityStateText,
  compatibilitySummary,
  createLatestRequestGate,
  currentCompatibilityState,
  initialPreviewState,
  previewIdentity,
} from "../src/utils/certificateCompatibility.ts";
import { notifyNodeConfigSaved } from "../src/utils/workflowNodeSaved.ts";

const t = (key: string, options?: Record<string, unknown>) => {
  const messages: Record<string, string> = {
    "certificate.compatibility.summary.minimum": "Estimated Android {{version}}+",
    "certificate.compatibility.summary.ranges": "Estimated Android {{versions}}",
    "certificate.compatibility.summary.unknown": "Unknown",
    "certificate.compatibility.reason.other": "Unknown reason",
    "certificate.compatibility.loading": "Loading",
    "certificate.compatibility.unavailable": "Unavailable",
  };
  const message = messages[key] ?? (options?.defaultValue as string) ?? key;
  return message.replace(/\{\{(\w+)\}\}/g, (_, name: string) => String(options?.[name]));
};
const result = (statuses: string[]): CertificateCompatibilityResult => ({
  status: "compatible",
  reason: "supported_versions",
  estimated: true,
  supportedVersions: [],
  profiles: statuses.map((status, i) => ({ version: ["4.1", "7", "7.1.1", "17"][i], status: status as "trusted", reason: "", roots: [] })),
  dataVersion: "test",
  evaluatedAt: "2026-01-01T00:00:00Z",
  scope: "android_system_roots",
  oldestVersion: "4.1",
  newestVersion: "17",
});

test("only a contiguous trusted suffix produces a minimum; earlier isolated successes remain visible", () => {
  assert.equal(compatibilitySummary(result(["unknown", "not_trusted", "trusted", "trusted"]), t), "Estimated Android 7.1.1+");
  const discontinuous = result(["trusted", "not_trusted", "trusted", "trusted"]);
  discontinuous.minimumVersion = "7.1.1";
  assert.equal(compatibilitySummary(discontinuous, t), "Estimated Android 4.1, 7.1.1–17");
  assert.equal(compatibilitySummary(result(["trusted", "trusted", "unknown", "not_trusted"]), t), "Estimated Android 4.1–7");
  assert.equal(compatibilitySummary({ ...result([]), status: "unknown" }, t), "Unknown");
});

test("batching deduplicates IDs and stays within the server's 100-ID limit", () => {
  const ids = Array.from({ length: 205 }, (_, i) => `cert-${i}`);
  const chunks = chunkCertificateIds(["", ...ids, ...ids.slice(0, 8)]);
  assert.deepEqual(
    chunks.map((chunk) => chunk.length),
    [100, 100, 5]
  );
  assert.deepEqual(chunks.flat(), ids);
  assert.deepEqual(chunkCertificateIds([]), []);
});

test("changed PEMs and sources immediately stop displaying a previous compatible result", () => {
  const key = previewIdentity("form", " PEM A ");
  const stored = { key, state: { phase: "ready" as const, result: result(["trusted"]) } };
  assert.equal(currentCompatibilityState(stored, previewIdentity("form", "PEM A"), initialPreviewState("form", "PEM A")).phase, "ready");
  const changed = currentCompatibilityState(stored, previewIdentity("form", "PEM B"), initialPreviewState("form", "PEM B"));
  assert.equal(compatibilityStateText(changed, t), "Loading");
  assert.equal(
    currentCompatibilityState(stored, previewIdentity("url", "https://example.test/cert"), initialPreviewState("url", "https://example.test/cert")).phase,
    "deferred"
  );
  assert.equal(initialPreviewState("form", "  ").phase, "idle");
  assert.equal(compatibilityStateText({ phase: "unavailable" }, t), "Unavailable");
  assert.equal(compatibilityReason("future_reason", t), "Unknown reason");
});

test("out-of-order requests and cleanup cannot replace the current input's result", async () => {
  const gate = createLatestRequestGate();
  let visible = "loading";
  const oldResponse = Promise.withResolvers<string>();
  const oldRequest = gate.next();
  const oldFinished = oldResponse.promise.then((value) => {
    if (gate.isCurrent(oldRequest)) visible = value;
  });
  const newRequest = gate.next();
  if (gate.isCurrent(newRequest)) visible = "new-result";
  oldResponse.resolve("old-compatible-result");
  await oldFinished;
  assert.equal(visible, "new-result");
  gate.invalidate();
  assert.equal(gate.isCurrent(newRequest), false);
});

test("informational save callbacks cannot block saving, even when they fail or remain pending", async () => {
  assert.doesNotThrow(() => notifyNodeConfigSaved(undefined, {}));
  assert.doesNotThrow(() =>
    notifyNodeConfigSaved(() => {
      throw new Error("toast failed");
    }, {})
  );
  notifyNodeConfigSaved(async () => {
    throw new Error("async toast failed");
  }, {});
  let observed: unknown;
  const pending = Promise.withResolvers<void>();
  const values = { certificate: "pem" };
  assert.equal(
    notifyNodeConfigSaved((saved) => {
      observed = saved;
      return pending.promise;
    }, values),
    undefined
  );
  assert.equal(observed, values);
  pending.resolve();
  await new Promise<void>((resolve) => setImmediate(resolve));
});

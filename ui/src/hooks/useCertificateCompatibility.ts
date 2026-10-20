import { useEffect, useRef, useState } from "react";

import { analyzeCompatibility, batchCompatibility } from "@/api/certificates";
import { type CertificateCompatibilityState } from "@/domain/certificateCompatibility";
import {
  chunkCertificateIds,
  createLatestRequestGate,
  currentCompatibilityState,
  initialPreviewState,
  previewIdentity,
} from "@/utils/certificateCompatibility";

export function useCertificateCompatibility(ids: string[], revision: string | number = "") {
  const idsKey = JSON.stringify([...new Set(ids.filter(Boolean))]);
  const key = JSON.stringify([idsKey, revision]);
  const gate = useRef(createLatestRequestGate());
  const [stored, setStored] = useState<{ key: string; states: Record<string, CertificateCompatibilityState> }>({ key: "", states: {} });

  useEffect(() => {
    const request = gate.current.next();
    const currentGate = gate.current;
    const chunks = chunkCertificateIds(JSON.parse(idsKey));
    const initial = Object.fromEntries(chunks.flat().map((id) => [id, { phase: "loading" } as CertificateCompatibilityState]));
    setStored({ key, states: initial });
    for (const chunk of chunks) {
      batchCompatibility(chunk)
        .then((results) => {
          if (!currentGate.isCurrent(request)) return;
          setStored((previous) => ({
            key,
            states: {
              ...previous.states,
              ...Object.fromEntries(chunk.map((id) => [id, results[id] ? { phase: "ready", result: results[id] } : { phase: "unavailable" }])),
            },
          }));
        })
        .catch(() => {
          if (!currentGate.isCurrent(request)) return;
          setStored((previous) => ({ key, states: { ...previous.states, ...Object.fromEntries(chunk.map((id) => [id, { phase: "unavailable" }])) } }));
        });
    }
    return () => {
      currentGate.invalidate();
    };
  }, [key, idsKey]);

  return stored.key === key ? stored.states : Object.fromEntries(ids.map((id) => [id, { phase: "loading" } as CertificateCompatibilityState]));
}

export function useCertificateCompatibilityPreview(source: string | undefined, certificate: string | undefined, enabled = true) {
  const key = previewIdentity(source, certificate);
  const gate = useRef(createLatestRequestGate());
  const [stored, setStored] = useState<{ key: string; state: CertificateCompatibilityState }>({ key: "", state: { phase: "idle" } });

  useEffect(() => {
    const request = gate.current.next();
    const currentGate = gate.current;
    const [currentSource, pem] = JSON.parse(key) as [string, string];
    const initial = initialPreviewState(currentSource, pem);
    setStored({ key, state: initial });
    if (!enabled || initial.phase !== "loading") return;
    const timer = setTimeout(() => {
      analyzeCompatibility(pem)
        .then((result) => {
          if (currentGate.isCurrent(request)) setStored({ key, state: { phase: "ready", result } });
        })
        .catch(() => {
          if (currentGate.isCurrent(request)) setStored({ key, state: { phase: "unavailable" } });
        });
    }, 400);
    return () => {
      clearTimeout(timer);
      currentGate.invalidate();
    };
  }, [key, enabled]);

  return { key, state: currentCompatibilityState(stored, key, initialPreviewState(source, certificate)) };
}

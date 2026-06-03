import React, { useState } from "react";
import { Atom } from "lucide-react";
import { ShorRsaDiagram } from "./ShorRsaDiagram.tsx";
import { apiUrl } from "../lib/api.ts";

export function QuantumDemoPanel({ onComplete }: { onComplete?: () => void }) {
  const [data, setData] = useState<Record<string, unknown> | null>(null);
  const [loading, setLoading] = useState(false);

  const run = async () => {
    setLoading(true);
    try {
      const res = await fetch(apiUrl("/api/quantum/rsa-demo"), { method: "POST" });
      setData((await res.json()) as Record<string, unknown>);
      onComplete?.();
    } finally {
      setLoading(false);
    }
  };

  const steps = (data?.steps as string[]) || [];

  return (
    <div className="bg-white border border-slate-200 rounded-2xl p-6 space-y-4 shadow-sm">
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-bold text-slate-900 flex items-center gap-2">
          <Atom className="w-6 h-6 text-violet-700" />
          Quantum attack: RSA + simulated Shor
        </h3>
        <button
          type="button"
          onClick={run}
          disabled={loading}
          className="px-4 py-2 bg-violet-500/20 hover:bg-violet-500/30 text-violet-800 text-sm font-bold rounded-lg border border-violet-500/30 disabled:opacity-50"
        >
          {loading ? "Running…" : "Run demo"}
        </button>
      </div>
      <p className="text-xs text-slate-500">
        Small primes for education only. Shows encryption, then simulated factorization of n to recover the private key.
      </p>
      <ShorRsaDiagram />
      {data && (
        <div className="space-y-3 text-xs font-mono text-slate-600">
          <p>
            n = {String(data.n)}, p×q = {String(data.p)}×{String(data.q)} · ciphertext blocks (preview):{" "}
            {JSON.stringify((data.ciphertext as number[])?.slice(0, 6) ?? [])}
            {(Array.isArray(data.ciphertext) && data.ciphertext.length > 6 ? " …" : "")}
          </p>
          <div className="space-y-1 max-h-[200px] overflow-y-auto">
            {steps.map((s, i) => (
              <p key={i} className="text-[11px] text-slate-600 border-l-2 border-violet-500/40 pl-2">
                {s}
              </p>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

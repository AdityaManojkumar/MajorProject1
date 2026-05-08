import React, { useState } from "react";
import { Shield, Loader2 } from "lucide-react";

export function PqcApiPanel() {
  const [out, setOut] = useState<Record<string, unknown> | null>(null);
  const [loading, setLoading] = useState(false);
  const [fetchedAt, setFetchedAt] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/pqc/demo");
      setOut((await res.json()) as Record<string, unknown>);
      setFetchedAt(new Date().toLocaleTimeString());
    } finally {
      setLoading(false);
    }
  };

  const algorithms =
    (out?.algorithms as Array<{ name: string; family: string; quantumResistance: string; steps: string[] }>) || [];

  return (
    <div className="bg-zinc-900/40 border border-white/5 rounded-2xl p-6 space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-bold text-white flex items-center gap-2">
          <Shield className="w-6 h-6 text-emerald-400" />
          NIST-style algorithms (reference only)
        </h3>
        <button
          type="button"
          onClick={load}
          disabled={loading}
          className="px-4 py-2 bg-emerald-500/20 hover:bg-emerald-500/30 disabled:opacity-60 text-emerald-200 text-sm font-bold rounded-lg border border-emerald-500/30 flex items-center gap-2"
        >
          {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : null}
          {loading ? "Fetching…" : "Fetch from API"}
        </button>
      </div>
      <p className="text-xs text-zinc-500">
        The <strong className="text-zinc-400">simulation above</strong> is the live proof: toy lattice vs broken RSA. This
        section is optional reading — short summaries of Kyber, Dilithium, and SPHINCS+ for your report or viva; it does
        not perform real PQ crypto.
      </p>
      <p className="text-xs text-zinc-600">{String(out?.note || "")}</p>
      {fetchedAt && (
        <p className="text-[10px] font-mono text-emerald-500/80">Last fetch: {fetchedAt} · GET /api/pqc/demo</p>
      )}
      <div className="grid gap-4 md:grid-cols-3">
        {algorithms.length === 0 && (
          <p className="text-xs text-zinc-600 md:col-span-3">Click “Fetch from API” to pull algorithm outlines from the server.</p>
        )}
        {algorithms.map((a) => (
          <div key={a.name} className="p-4 rounded-xl bg-black/30 border border-white/5">
            <p className="text-sm font-bold text-white">{a.name}</p>
            <p className="text-[10px] text-zinc-500">{a.family}</p>
            <p className="text-xs text-emerald-400/80 mt-1">{a.quantumResistance}</p>
            <ul className="mt-2 text-[11px] text-zinc-400 list-disc pl-4">
              {a.steps.map((s, i) => (
                <li key={i}>{s}</li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </div>
  );
}

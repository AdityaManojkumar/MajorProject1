import React, { useState, useEffect, useRef } from "react";
import { Shield, ShieldAlert, ShieldCheck, Loader2, Terminal } from "lucide-react";

type ProtectionResult = {
  runId: string;
  completedAt: string;
  processingMs: number;
  summary: string;
  secretPayload: string;
  rsa: {
    modulusN: number;
    bitLength: number;
    ciphertextBlocks: number;
    attackLabel: string;
    attackerRecoveredSecret: string;
    secretLeaked: boolean;
    explanation: string;
  };
  lattice: {
    ciphertextBitBlocks: number;
    schemeNote: string;
    attackerRecoveredGarbage: string;
    legitimateRecoveredSecret: string;
    latticeProtectsPayload: boolean;
    explanation: string;
  };
  takeaway: string;
};

const PIPELINE_TICKS = [
  "[crypto] Deriving RSA modulus from seeded primes…",
  "[crypto] Running textbook modular exponentiation (encrypt)…",
  "[bench] Lattice encapsulation — sampling noise vectors…",
  "[bench] Simulating adversary without secret vector…",
  "[net] POST /api/pqc/protection-demo → awaiting server transcript…",
];

export function PqcProtectionPanel() {
  const [message, setMessage] = useState("Secret payload: session AW7 • rotate credentials");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ProtectionResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pipelineIdx, setPipelineIdx] = useState(0);
  const [showCards, setShowCards] = useState(0);
  const tickRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    if (!loading) {
      setPipelineIdx(0);
      if (tickRef.current) clearInterval(tickRef.current);
      return;
    }
    tickRef.current = setInterval(() => {
      setPipelineIdx((i) => (i + 1) % PIPELINE_TICKS.length);
    }, 380);
    return () => {
      if (tickRef.current) clearInterval(tickRef.current);
    };
  }, [loading]);

  useEffect(() => {
    if (!result) {
      setShowCards(0);
      return;
    }
    setShowCards(0);
    const t = window.setInterval(() => {
      setShowCards((s) => {
        if (s >= 4) {
          clearInterval(t);
          return 4;
        }
        return s + 1;
      });
    }, 160);
    return () => clearInterval(t);
  }, [result]);

  const run = async () => {
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await fetch("/api/pqc/protection-demo", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: message.trim() || undefined }),
      });
      if (!res.ok) throw new Error(await res.text());
      setResult((await res.json()) as ProtectionResult);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Request failed");
      setResult(null);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="bg-zinc-900/40 border border-white/5 rounded-2xl p-6 space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-4">
        <div>
          <h3 className="text-lg font-bold text-white flex items-center gap-2">
            <Shield className="w-6 h-6 text-cyan-400" />
            Live crypto benchmark — RSA vs lattice layer
          </h3>
          <p className="text-xs text-zinc-500 mt-2 max-w-xl leading-relaxed">
            Server-side engine compares RSA confidentiality against a lattice-style encapsulation of the same payload. Each run gets
            a unique job id and timing from the backend.
          </p>
        </div>
        <button
          type="button"
          onClick={run}
          disabled={loading}
          className="shrink-0 px-5 py-2.5 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white text-sm font-bold rounded-xl flex items-center gap-2 shadow-lg shadow-cyan-900/30"
        >
          {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Terminal className="w-4 h-4" />}
          Execute benchmark
        </button>
      </div>

      <div className="space-y-2">
        <label className="text-[10px] font-bold text-zinc-500 uppercase tracking-wider">Payload to seal</label>
        <input
          type="text"
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          maxLength={48}
          className="w-full px-4 py-2 bg-black/40 border border-white/10 rounded-xl text-sm text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:ring-2 focus:ring-cyan-500/40"
          placeholder="Secret string — both sides encrypt this"
        />
      </div>

      {loading && (
        <div className="rounded-xl border border-cyan-500/30 bg-black/50 p-4 font-mono text-[11px] text-emerald-400/90 space-y-2">
          <p className="text-zinc-500 flex items-center gap-2">
            <span className="inline-block w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
            {PIPELINE_TICKS[pipelineIdx]}
          </p>
          <div className="h-1 rounded-full bg-zinc-800 overflow-hidden">
            <div
              className="h-full bg-gradient-to-r from-cyan-600 to-emerald-500 transition-all duration-300"
              style={{ width: `${((pipelineIdx + 1) / PIPELINE_TICKS.length) * 100}%` }}
            />
          </div>
        </div>
      )}

      {error && (
        <p className="text-sm text-red-400 border border-red-500/30 rounded-lg px-3 py-2 bg-red-950/40">{error}</p>
      )}

      {result && (
        <div className="space-y-4 transition-opacity duration-300">
          <div className="flex flex-wrap gap-3 text-[11px] font-mono border border-white/10 rounded-xl px-4 py-3 bg-black/40">
            <span className="text-zinc-500">job</span>
            <span className="text-cyan-300">{result.runId}</span>
            <span className="text-zinc-600">|</span>
            <span className="text-zinc-500">wall time</span>
            <span className="text-emerald-400">{result.processingMs} ms</span>
            <span className="text-zinc-600">|</span>
            <span className="text-zinc-500">completed</span>
            <span className="text-zinc-300">{new Date(result.completedAt).toLocaleString()}</span>
          </div>

          <p
            className={`text-sm border rounded-xl px-4 py-3 bg-cyan-950/20 transition-opacity duration-300 ${
              showCards >= 1 ? "opacity-100 border-cyan-500/20 text-cyan-200/90" : "opacity-0"
            }`}
          >
            {result.summary}
          </p>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div
              className={`rounded-xl border border-red-500/25 bg-red-950/15 p-4 space-y-3 transition-all duration-300 ${
                showCards >= 2 ? "opacity-100 translate-y-0" : "opacity-0 translate-y-2"
              }`}
            >
              <div className="flex items-center gap-2 text-red-300 font-bold text-sm">
                <ShieldAlert className="w-5 h-5" />
                RSA track (broken after factorization)
              </div>
              <p className="text-[11px] text-zinc-400">{result.rsa.explanation}</p>
              <div className="text-[10px] font-mono text-zinc-500 space-y-1">
                <p>
                  n = {result.rsa.modulusN} (~{result.rsa.bitLength} bit) · {result.rsa.ciphertextBlocks} blocks
                </p>
                <p className="text-red-200/90">{result.rsa.attackLabel}</p>
              </div>
              <div className="rounded-lg bg-black/30 p-3 border border-red-500/20">
                <p className="text-[10px] uppercase text-red-400 font-bold mb-1">Intercept + recover</p>
                <p className="text-sm font-mono text-red-100 break-all">{result.rsa.attackerRecoveredSecret}</p>
                {result.rsa.secretLeaked && (
                  <p className="text-[10px] text-red-400 mt-2">Plaintext recovered — RSA confidentiality fails.</p>
                )}
              </div>
            </div>

            <div
              className={`rounded-xl border border-emerald-500/25 bg-emerald-950/15 p-4 space-y-3 transition-all duration-300 ${
                showCards >= 3 ? "opacity-100 translate-y-0" : "opacity-0 translate-y-2"
              }`}
            >
              <div className="flex items-center gap-2 text-emerald-300 font-bold text-sm">
                <ShieldCheck className="w-5 h-5" />
                Lattice track (same payload)
              </div>
              <p className="text-[11px] text-zinc-400">{result.lattice.explanation}</p>
              <p className="text-[10px] text-emerald-400/80">{result.lattice.schemeNote}</p>
              <div className="text-[10px] font-mono text-zinc-500">{result.lattice.ciphertextBitBlocks} bit-ciphertext blocks</div>
              <div className="rounded-lg bg-black/30 p-3 border border-orange-500/20">
                <p className="text-[10px] uppercase text-orange-300 font-bold mb-1">Wrong secret vector</p>
                <p className="text-xs font-mono text-zinc-400 break-all">{result.lattice.attackerRecoveredGarbage}</p>
              </div>
              <div className="rounded-lg bg-black/30 p-3 border border-emerald-500/20">
                <p className="text-[10px] uppercase text-emerald-400 font-bold mb-1">Legitimate receiver</p>
                <p className="text-sm font-mono text-emerald-100 break-all">{result.lattice.legitimateRecoveredSecret}</p>
                {result.lattice.latticeProtectsPayload && (
                  <p className="text-[10px] text-emerald-400/90 mt-2">Payload intact without factorization.</p>
                )}
              </div>
            </div>
          </div>

          <p
            className={`text-xs text-zinc-500 border-t border-white/5 pt-4 transition-opacity duration-500 ${
              showCards >= 4 ? "opacity-100" : "opacity-0"
            }`}
          >
            {result.takeaway}
          </p>
        </div>
      )}
    </div>
  );
}

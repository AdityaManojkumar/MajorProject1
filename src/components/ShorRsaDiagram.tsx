import React from "react";

/**
 * Educational pipeline: RSA confidentiality vs Shor-class factorization (not literal circuit gates).
 */
export function ShorRsaDiagram() {
  return (
    <div className="rounded-xl border border-violet-500/25 bg-black/30 p-4 overflow-x-auto">
      <p className="text-[11px] font-bold text-violet-300 uppercase tracking-wider mb-3">RSA → Shor pipeline (concept)</p>
      <svg viewBox="0 0 920 200" className="w-full min-w-[640px] h-[180px] text-[11px]" aria-label="RSA Shor pipeline diagram">
        <defs>
          <marker id="arrow" markerWidth="8" markerHeight="8" refX="6" refY="4" orient="auto">
            <path d="M0,0 L8,4 L0,8 Z" fill="#a78bfa" />
          </marker>
        </defs>

        <rect x="8" y="24" width="120" height="56" rx="8" fill="#1e1b4b" stroke="#818cf8" strokeWidth="1.5" />
        <text x="68" y="48" textAnchor="middle" fill="#e0e7ff" fontSize="12" fontWeight="bold">
          RSA keygen
        </text>
        <text x="68" y="66" textAnchor="middle" fill="#a5b4fc" fontSize="10">
          n = p×q (tiny primes)
        </text>

        <line x1="128" y1="52" x2="168" y2="52" stroke="#a78bfa" strokeWidth="2" markerEnd="url(#arrow)" />

        <rect x="168" y="24" width="120" height="56" rx="8" fill="#1e1b4b" stroke="#818cf8" strokeWidth="1.5" />
        <text x="228" y="48" textAnchor="middle" fill="#e0e7ff" fontSize="12" fontWeight="bold">
          Encrypt
        </text>
        <text x="228" y="66" textAnchor="middle" fill="#a5b4fc" fontSize="10">
          c = m^e mod n
        </text>

        <line x1="288" y1="52" x2="328" y2="52" stroke="#a78bfa" strokeWidth="2" markerEnd="url(#arrow)" />

        <rect x="328" y="12" width="200" height="80" rx="8" fill="#3b0764" stroke="#c084fc" strokeWidth="2" />
        <text x="428" y="38" textAnchor="middle" fill="#f5d0fe" fontSize="13" fontWeight="bold">
          Shor (simulator)
        </text>
        <text x="428" y="58" textAnchor="middle" fill="#e9d5ff" fontSize="10">
          Period finding → factors p,q
        </text>
        <text x="428" y="76" textAnchor="middle" fill="#ddd6fe" fontSize="9">
          (Educational demo — web uses simulated factors)
        </text>

        <line x1="528" y1="52" x2="568" y2="52" stroke="#a78bfa" strokeWidth="2" markerEnd="url(#arrow)" />

        <rect x="568" y="24" width="130" height="56" rx="8" fill="#1e1b4b" stroke="#818cf8" strokeWidth="1.5" />
        <text x="633" y="48" textAnchor="middle" fill="#e0e7ff" fontSize="12" fontWeight="bold">
          Recover φ(n), d
        </text>
        <text x="633" y="66" textAnchor="middle" fill="#a5b4fc" fontSize="10">
          attacker path
        </text>

        <line x1="698" y1="52" x2="738" y2="52" stroke="#a78bfa" strokeWidth="2" markerEnd="url(#arrow)" />

        <rect x="738" y="24" width="130" height="56" rx="8" fill="#450a0a" stroke="#f87171" strokeWidth="1.5" />
        <text x="803" y="48" textAnchor="middle" fill="#fecaca" fontSize="12" fontWeight="bold">
          Decrypt
        </text>
        <text x="803" y="66" textAnchor="middle" fill="#fca5a5" fontSize="10">
          m = c^d mod n
        </text>

        <text x="460" y="130" textAnchor="middle" fill="#71717a" fontSize="10">
          At scale: migrate to PQC (Kyber / Dilithium / hash sigs) before RSA-only confidentiality fails.
        </text>
      </svg>
    </div>
  );
}

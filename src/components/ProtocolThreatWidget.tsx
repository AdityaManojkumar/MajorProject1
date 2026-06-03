import React, { useEffect, useState } from "react";
import { Layers, Shield, RefreshCw } from "lucide-react";
import type { ProtocolThreatRow } from "../types/event";
import { apiUrl } from "../lib/api.ts";

function mitigationBadge(status: string | null) {
  switch (status) {
    case "applied":
      return "bg-emerald-50 text-emerald-800 border-emerald-200";
    case "pending":
      return "bg-amber-50 text-amber-800 border-amber-200";
    default:
      return "bg-slate-50 text-slate-500 border-slate-200";
  }
}

function cryptoBadge(threatClass: string | null) {
  if (threatClass === "quantum_cryptographic") {
    return "text-purple-700 bg-purple-50 border-purple-200";
  }
  if (threatClass === "classical") {
    return "text-blue-700 bg-blue-50 border-blue-200";
  }
  return "text-slate-500 bg-slate-50 border-slate-200";
}

export function ProtocolThreatWidget({ refreshKey = 0 }: { refreshKey?: number }) {
  const [threats, setThreats] = useState<ProtocolThreatRow[]>([]);
  const [loading, setLoading] = useState(true);

  const load = () => {
    setLoading(true);
    fetch(apiUrl("/api/protocol/threats"))
      .then((r) => r.json())
      .then((data) => setThreats(Array.isArray(data) ? data : []))
      .catch(() => setThreats([]))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    load();
  }, [refreshKey]);

  return (
    <div className="bg-white border border-slate-200 rounded-2xl p-6 shadow-sm">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-bold text-slate-900 flex items-center gap-2">
          <Layers className="w-5 h-5 text-cyan-700" />
          Protocol threat matrix
        </h3>
        <button
          type="button"
          onClick={load}
          className="p-2 rounded-lg hover:bg-slate-100 text-slate-500"
          aria-label="Refresh threats"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
        </button>
      </div>
      <p className="text-xs text-slate-500 mb-4">
        Layer-aware view from the Protocol Analysis Layer — attack type, protocol, OSI layer, and mitigation status after AI
        classification.
      </p>

      <div className="overflow-x-auto rounded-xl border border-slate-200">
        <table className="w-full text-left text-xs border-collapse">
          <thead>
            <tr className="bg-slate-50 text-[10px] uppercase text-slate-500">
              <th className="p-3">Time</th>
              <th className="p-3">Attack type</th>
              <th className="p-3">Protocol</th>
              <th className="p-3">OSI layer</th>
              <th className="p-3">Threat class</th>
              <th className="p-3">Mitigation</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-200">
            {threats.length === 0 ? (
              <tr>
                <td colSpan={6} className="p-4 text-slate-500 italic">
                  {loading ? "Loading…" : "No classified threats yet — run AI analysis on pending events."}
                </td>
              </tr>
            ) : (
              threats.slice(0, 12).map((t) => {
                let metaAttack = t.attack_type;
                if (t.attack_metadata_json) {
                  try {
                    const m = JSON.parse(t.attack_metadata_json) as { attack_type?: string };
                    if (m.attack_type) metaAttack = m.attack_type;
                  } catch {
                    /* ignore */
                  }
                }
                return (
                  <tr key={t.id} className="hover:bg-slate-50">
                    <td className="p-3 font-mono text-slate-600 whitespace-nowrap">
                      {new Date(t.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="p-3 font-semibold text-orange-700 capitalize">
                      {(metaAttack || "—").replace(/_/g, " ")}
                    </td>
                    <td className="p-3 font-mono text-cyan-800">{t.protocol || "—"}</td>
                    <td className="p-3 text-slate-700">{t.osi_layer || "—"}</td>
                    <td className="p-3">
                      <span
                        className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full border text-[10px] font-bold uppercase ${cryptoBadge(t.crypto_threat_class)}`}
                      >
                        <Shield className="w-3 h-3" />
                        {t.crypto_threat_class === "quantum_cryptographic"
                          ? "Quantum"
                          : t.crypto_threat_class === "classical"
                            ? "Classical"
                            : "—"}
                      </span>
                    </td>
                    <td className="p-3">
                      <span
                        className={`inline-block px-2 py-0.5 rounded-full border text-[10px] font-bold uppercase ${mitigationBadge(t.mitigation_status)}`}
                      >
                        {t.mitigation_status || "none"}
                      </span>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

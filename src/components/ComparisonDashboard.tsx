import React, { useEffect, useState } from "react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Legend,
  CartesianGrid,
} from "recharts";
import type { DashboardStats, SecurityEvent } from "../types/event";

const comparisonRows = [
  { factor: "Attack type", classical: "DDoS, brute force, botnet, scans", quantum: "Crypto break (RSA / ECC)" },
  { factor: "Target", classical: "Network services, logins", quantum: "Public keys & ciphertext" },
  { factor: "Method", classical: "Traffic flood, guessing, replay from IDS datasets", quantum: "Shor-style period finding → factor n" },
  { factor: "Example", classical: "Replay jobs + Overview scenarios + Live login", quantum: "Quantum tab RSA demo (tiny keys)" },
  { factor: "Impact", classical: "Service disruption, account abuse", quantum: "Confidentiality loss if keys break" },
  { factor: "Defense", classical: "IDS, AI classification, monitoring", quantum: "Post-quantum cryptography (PQC)" },
];

const tableWrap =
  "w-full border-collapse overflow-hidden rounded-xl border border-white/10 text-left text-[12px] leading-snug";
const th =
  "border-b border-white/10 bg-zinc-800/90 px-3 py-2.5 font-bold text-zinc-300 first:rounded-tl-xl last:rounded-tr-xl";
const td = "border-b border-white/[0.06] px-3 py-2.5 text-zinc-400 align-top";
const tdStrong = "border-b border-white/[0.06] px-3 py-2.5 font-semibold text-zinc-200 align-top";
const trStripe = "even:bg-white/[0.03]";

export function ComparisonDashboard({
  events,
  refreshKey = 0,
}: {
  events: SecurityEvent[];
  refreshKey?: number;
}) {
  const [stats, setStats] = useState<DashboardStats | null>(null);

  useEffect(() => {
    fetch("/api/stats")
      .then((r) => r.json())
      .then(setStats)
      .catch(() => setStats(null));
  }, [events, refreshKey]);

  const classCounts = events.reduce(
    (acc, e) => {
      const c = e.classification || "unclassified";
      acc[c] = (acc[c] || 0) + 1;
      return acc;
    },
    {} as Record<string, number>
  );

  const pieLike = Object.entries(classCounts).map(([name, value]) => ({ name, value }));

  const classicalSurface = stats?.classicalDemoTraffic ?? 0;
  const quantumDemos = stats?.quantumVulnerabilityDemos ?? 0;
  const datasetN = stats?.datasetInjectedEvents ?? 0;
  const simN = stats?.simulatedAttackEvents ?? 0;
  const loginN = stats?.loginDemoEvents ?? 0;

  const demoCompare = [
    {
      name: "Classical vs quantum (counts)",
      classical: classicalSurface,
      quantum_crypto: quantumDemos,
    },
  ];

  const breakdown = [
    { name: "Replay / batch rows", count: datasetN },
    { name: "Legacy synthetic API", count: simN },
    { name: "Login monitor events", count: loginN },
    { name: "Quantum RSA demos (UI)", count: quantumDemos },
  ];

  return (
    <div className="space-y-8">
      {/* —— Tables first: quick scan —— */}
      <div className="rounded-2xl border border-white/10 bg-gradient-to-br from-zinc-900/80 to-zinc-950/80 p-6 space-y-6">
        <div>
          <h3 className="text-lg font-bold text-white mb-1">Classical attack demos vs quantum crypto threat</h3>
          <p className="text-xs text-zinc-500 max-w-3xl">
            Tables below mirror the charts: <strong className="text-zinc-400">classical</strong> counts are replay jobs,
            overview scenarios, and login monitor volume. <strong className="text-zinc-400">Quantum</strong> counts RSA/Shor demo
            runs from the Quantum tab — not packet blocking.
          </p>
        </div>

        <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
          <div className="space-y-2">
            <h4 className="text-[11px] font-bold uppercase tracking-wider text-blue-300">Table 1 — Demo event sources (server)</h4>
            <div className="overflow-x-auto rounded-xl">
              <table className={tableWrap}>
                <thead>
                  <tr>
                    <th className={th}>Source</th>
                    <th className={`${th} w-24 text-right tabular-nums`}>Count</th>
                    <th className={th}>What it is</th>
                  </tr>
                </thead>
                <tbody>
                  <tr className={trStripe}>
                    <td className={tdStrong}>Replay / batch inject</td>
                    <td className={`${td} text-right tabular-nums text-blue-200`}>{datasetN}</td>
                    <td className={td}>Rows ingested from automated replay jobs (ops pipeline)</td>
                  </tr>
                  <tr className={trStripe}>
                    <td className={tdStrong}>Legacy simulated API</td>
                    <td className={`${td} text-right tabular-nums text-blue-200`}>{simN}</td>
                    <td className={td}>Legacy synthetic API traffic (if any remains in the DB).</td>
                  </tr>
                  <tr className={trStripe}>
                    <td className={tdStrong}>Live login monitor</td>
                    <td className={`${td} text-right tabular-nums text-blue-200`}>{loginN}</td>
                    <td className={td}>Login attempts captured on the Live tab</td>
                  </tr>
                  <tr className="bg-blue-950/40 border-t border-blue-500/20">
                    <td className={`${tdStrong} text-blue-200`}>Classical demo surface (Σ)</td>
                    <td className={`${td} text-right tabular-nums font-bold text-blue-100`}>{classicalSurface}</td>
                    <td className={td}>Sum of the three rows above — “how much classical-style demo traffic”</td>
                  </tr>
                  <tr className={trStripe}>
                    <td className={tdStrong}>Quantum RSA demos</td>
                    <td className={`${td} text-right tabular-nums text-purple-300`}>{quantumDemos}</td>
                    <td className={td}>Runs of the in-app RSA / Shor educational demo (Quantum tab)</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

          <div className="space-y-2">
            <h4 className="text-[11px] font-bold uppercase tracking-wider text-purple-300">
              Table 2 — Head-to-head (same numbers, different role)
            </h4>
            <div className="overflow-x-auto rounded-xl">
              <table className={tableWrap}>
                <thead>
                  <tr>
                    <th className={th}>Dimension</th>
                    <th className={`${th} text-blue-300`}>Classical demos</th>
                    <th className={`${th} text-purple-300`}>Quantum crypto demos</th>
                  </tr>
                </thead>
                <tbody>
                  <tr className={trStripe}>
                    <td className={tdStrong}>Volume (events)</td>
                    <td className={`${td} tabular-nums text-blue-200`}>{classicalSurface}</td>
                    <td className={`${td} tabular-nums text-purple-200`}>{quantumDemos}</td>
                  </tr>
                  <tr className={trStripe}>
                    <td className={tdStrong}>What we’re measuring</td>
                    <td className={td}>IDS-style / login / injected traffic you drove for the project</td>
                    <td className={td}>How often the UI ran the tiny-key RSA break narrative</td>
                  </tr>
                  <tr className={trStripe}>
                    <td className={tdStrong}>Real-time defence?</td>
                    <td className={td}>AI + logs classify / highlight this traffic</td>
                    <td className={td}>No — illustrates future crypto risk; does not block packets</td>
                  </tr>
                  <tr className={trStripe}>
                    <td className={tdStrong}>Mitigation story</td>
                    <td className={td}>Monitoring, ML/heuristic classification, replay for evaluation</td>
                    <td className={td}>PQC tab + migration away from RSA-only confidentiality</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 pt-2">
          <div className="h-[280px]">
            <p className="text-[11px] font-bold text-zinc-400 uppercase tracking-wider mb-3">Chart — demo volume</p>
            <ResponsiveContainer width="100%" height="90%">
              <BarChart data={demoCompare} margin={{ top: 8, right: 8, left: 0, bottom: 8 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#ffffff08" vertical={false} />
                <XAxis dataKey="name" tick={{ fill: "#a1a1aa", fontSize: 11 }} />
                <YAxis tick={{ fill: "#a1a1aa", fontSize: 11 }} allowDecimals={false} />
                <Tooltip
                  contentStyle={{ background: "#18181b", border: "1px solid #3f3f46", borderRadius: "12px" }}
                  labelStyle={{ color: "#fafafa" }}
                />
                <Legend />
                <Bar dataKey="classical" name="Classical demo traffic (Σ)" fill="#3b82f6" radius={[6, 6, 0, 0]} />
                <Bar dataKey="quantum_crypto" name="Quantum RSA demos" fill="#a855f7" radius={[6, 6, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>

          <div className="h-[280px]">
            <p className="text-[11px] font-bold text-zinc-400 uppercase tracking-wider mb-3">Chart — breakdown</p>
            <ResponsiveContainer width="100%" height="90%">
              <BarChart data={breakdown} layout="vertical" margin={{ left: 8, right: 16 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#ffffff08" horizontal={false} />
                <XAxis type="number" tick={{ fill: "#a1a1aa", fontSize: 11 }} allowDecimals={false} />
                <YAxis type="category" dataKey="name" width={140} tick={{ fill: "#d4d4d8", fontSize: 10 }} />
                <Tooltip contentStyle={{ background: "#18181b", border: "1px solid #3f3f46", borderRadius: "12px" }} />
                <Bar dataKey="count" name="Events" fill="#10b981" radius={[0, 6, 6, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        <div className="space-y-2">
          <h4 className="text-[11px] font-bold uppercase tracking-wider text-orange-300">Table 3 — AI labels (database totals)</h4>
          <div className="overflow-x-auto rounded-xl">
            <table className={tableWrap}>
              <thead>
                <tr>
                  <th className={th}>Classification bucket</th>
                  <th className={`${th} w-28 text-right tabular-nums`}>Events</th>
                  <th className={th}>Meaning</th>
                </tr>
              </thead>
              <tbody>
                <tr className={trStripe}>
                  <td className={tdStrong}>Attack-like</td>
                  <td className={`${td} text-right tabular-nums text-orange-300`}>
                    {stats?.classicalAttacksDetected ?? "—"}
                  </td>
                  <td className={td}>confirmed_attack or ground_truth attack in DB</td>
                </tr>
                <tr className={trStripe}>
                  <td className={tdStrong}>Suspicious</td>
                  <td className={`${td} text-right tabular-nums text-yellow-300`}>{stats?.suspiciousEvents ?? "—"}</td>
                  <td className={td}>Flagged by classifier as suspicious</td>
                </tr>
                <tr className={trStripe}>
                  <td className={tdStrong}>Normal</td>
                  <td className={`${td} text-right tabular-nums text-emerald-300`}>{stats?.normalClassified ?? "—"}</td>
                  <td className={td}>Classified as normal traffic</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        <div className="space-y-2">
          <h4 className="text-[11px] font-bold uppercase tracking-wider text-emerald-300">Table 4 — This browser session (events in memory)</h4>
          <div className="overflow-x-auto rounded-xl">
            <table className={tableWrap}>
              <thead>
                <tr>
                  <th className={th}>Label</th>
                  <th className={`${th} w-28 text-right tabular-nums`}>Count</th>
                  <th className={th}>Note</th>
                </tr>
              </thead>
              <tbody>
                {pieLike.length === 0 ? (
                  <tr>
                    <td colSpan={3} className={`${td} text-zinc-500 italic`}>
                      No events loaded yet — open Logs / Live or replay a dataset.
                    </td>
                  </tr>
                ) : (
                  pieLike.map((row) => (
                    <tr key={row.name} className={trStripe}>
                      <td className={tdStrong}>{row.name}</td>
                      <td className={`${td} text-right tabular-nums text-emerald-200`}>{row.value}</td>
                      <td className={td}>Current UI session snapshot (may differ from DB totals)</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-zinc-900/40 border border-blue-500/20 rounded-xl p-4">
          <p className="text-[10px] text-zinc-500 uppercase">AI: attack-like</p>
          <p className="text-2xl font-bold text-orange-400">{stats?.classicalAttacksDetected ?? "—"}</p>
        </div>
        <div className="bg-zinc-900/40 border border-yellow-500/20 rounded-xl p-4">
          <p className="text-[10px] text-zinc-500 uppercase">AI: suspicious</p>
          <p className="text-2xl font-bold text-yellow-400">{stats?.suspiciousEvents ?? "—"}</p>
        </div>
        <div className="bg-zinc-900/40 border border-purple-500/20 rounded-xl p-4">
          <p className="text-[10px] text-zinc-500 uppercase">Quantum RSA demos</p>
          <p className="text-2xl font-bold text-purple-400">{stats?.quantumVulnerabilityDemos ?? 0}</p>
        </div>
        <div className="bg-zinc-900/40 border border-emerald-500/20 rounded-xl p-4">
          <p className="text-[10px] text-zinc-500 uppercase">PQC posture</p>
          <p className="text-xs font-bold text-emerald-400 leading-snug">{stats?.pqcStatus ?? "—"}</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-zinc-900/40 border border-white/5 rounded-2xl p-6 h-[320px]">
          <h4 className="text-sm font-bold text-white mb-4">AI threat labels (chart — same session as Table 4)</h4>
          <ResponsiveContainer width="100%" height="85%">
            <BarChart data={pieLike.length ? pieLike : [{ name: "none", value: 0 }]}>
              <XAxis dataKey="name" stroke="#71717a" fontSize={10} />
              <YAxis stroke="#71717a" fontSize={10} allowDecimals={false} />
              <Tooltip contentStyle={{ background: "#18181b", border: "1px solid #27272a" }} />
              <Legend />
              <Bar dataKey="value" fill="#10b981" name="Count" radius={[6, 6, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="bg-zinc-900/40 border border-white/5 rounded-2xl p-6 overflow-auto max-h-[420px]">
          <h4 className="text-sm font-bold text-white mb-3">Table 5 — Threat model: classical vs quantum</h4>
          <p className="text-[11px] text-zinc-500 mb-4">
            Same idea as the comparison matrix — row-by-row so it’s easy to quote in a report.
          </p>
          <div className="overflow-x-auto rounded-xl">
            <table className={tableWrap}>
              <thead>
                <tr>
                  <th className={`${th} min-w-[100px]`}>Factor</th>
                  <th className={`${th} text-blue-300 min-w-[140px]`}>Classical threat surface</th>
                  <th className={`${th} text-purple-300 min-w-[140px]`}>Quantum-era crypto threat</th>
                </tr>
              </thead>
              <tbody>
                {comparisonRows.map((r) => (
                  <tr key={r.factor} className={trStripe}>
                    <td className={`${tdStrong} text-zinc-300`}>{r.factor}</td>
                    <td className={td}>{r.classical}</td>
                    <td className={td}>{r.quantum}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <div className="overflow-x-auto rounded-xl border border-white/10 bg-zinc-950/50">
        <table className={tableWrap}>
          <thead>
            <tr>
              <th className={th}>Posture</th>
              <th className={th}>Status text</th>
            </tr>
          </thead>
          <tbody>
            <tr className={trStripe}>
              <td className={tdStrong}>PQC (dashboard)</td>
              <td className={td}>{stats?.pqcStatus ?? "—"}</td>
            </tr>
            <tr className={trStripe}>
              <td className={tdStrong}>RSA demo (educational)</td>
              <td className={td}>{stats?.rsaStatus ?? "—"}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  );
}

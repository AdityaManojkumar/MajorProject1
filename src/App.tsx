import React, { useState, useEffect, useCallback } from "react";
import {
  Shield,
  Activity,
  Lock,
  Terminal,
  Cpu,
  Globe,
  ShieldAlert,
  ShieldCheck,
  RefreshCw,
  Eye,
  Zap,
  X,
} from "lucide-react";
import { motion, AnimatePresence } from "motion/react";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  AreaChart,
  Area,
} from "recharts";
import type { SecurityEvent } from "./types/event";
import { RealtimePanel } from "./components/RealtimePanel.tsx";
import { LoginMonitor } from "./components/LoginMonitor.tsx";
import { ComparisonDashboard } from "./components/ComparisonDashboard.tsx";
import { QuantumDemoPanel } from "./components/QuantumDemoPanel.tsx";
import { PqcApiPanel } from "./components/PqcApiPanel.tsx";
import { PqcProtectionPanel } from "./components/PqcProtectionPanel.tsx";
import { ProtocolThreatWidget } from "./components/ProtocolThreatWidget.tsx";
import { apiUrl } from "./lib/api.ts";
import { chartAxis, chartGrid, chartTooltip } from "./lib/ui.ts";

interface BlockedIp {
  id: number;
  ip: string;
  reason: string;
  timestamp: string;
}

export default function App() {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [blockedIps, setBlockedIps] = useState<BlockedIp[]>([]);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [activeTab, setActiveTab] = useState<"overview" | "logs" | "live" | "quantum" | "pqc" | "defense">(
    "overview"
  );
  const [statsRefresh, setStatsRefresh] = useState(0);
  const [quickDataset, setQuickDataset] = useState<"cicids2017" | "nsl-kdd" | "unsw-nb15">("cicids2017");
  const [injectModal, setInjectModal] = useState<{
    id: number;
    sourceIp: string;
    datasetId: string;
    description: string;
    attackTypeLabel: string;
    groundTruth: string;
  } | null>(null);
  type AnalysisRow = {
    id: number;
    classification: string;
    attack_type: string | null;
    confidence: number;
    reason: string;
    httpStatus: number;
    statusLine: string;
    attackSummary: string;
    recommendation: string;
    osi_layer?: string;
    protocol?: string;
    severity_score?: number;
    crypto_threat_class?: string;
    mitigation_hint?: string;
  };
  const [analysisReport, setAnalysisReport] = useState<{
    processed: number;
    source: string;
    results: AnalysisRow[];
  } | null>(null);
  const [analysisError, setAnalysisError] = useState<string | null>(null);
  const [injectErr, setInjectErr] = useState<string | null>(null);

  const fetchBlockedIps = useCallback(async () => {
    try {
      const blockedRes = await fetch(apiUrl("/api/blocked-ips"));
      if (blockedRes.ok) {
        setBlockedIps((await blockedRes.json()) as BlockedIp[]);
      }
    } catch (e) {
      console.error("Blocked IP fetch error:", e);
    }
  }, []);

  const fetchData = useCallback(async () => {
    try {
      const [evRes, blockedRes] = await Promise.all([
        fetch(apiUrl("/api/events")),
        fetch(apiUrl("/api/blocked-ips")),
      ]);
      setEvents((await evRes.json()) as SecurityEvent[]);
      if (blockedRes.ok) {
        setBlockedIps((await blockedRes.json()) as BlockedIp[]);
      }
    } catch (e) {
      console.error("Fetch Error:", e);
    }
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const onEventMessage = useCallback((ev: SecurityEvent) => {
    setEvents((prev) => {
      if (prev.some((p) => p.id === ev.id)) return prev;
      return [ev, ...prev].slice(0, 250);
    });
  }, []);

  const onEventAnalyzed = useCallback((ev: SecurityEvent) => {
    setEvents((prev) => prev.map((p) => (p.id === ev.id ? { ...p, ...ev } : p)));
  }, []);

  const injectDatasetAttack = async (attackType: string) => {
    setInjectErr(null);
    try {
      const res = await fetch(apiUrl("/api/sim/inject-sample"), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ dataset: quickDataset, attackType }),
      });
      const data = (await res.json()) as {
        ok?: boolean;
        inject?: {
          id: number;
          sourceIp: string;
          datasetId: string;
          description: string;
          attackTypeLabel: string;
          groundTruth: string;
        };
        error?: string;
      };
      if (!res.ok) {
        setInjectErr(data.error || "Injection failed");
        return;
      }
      if (data.inject) setInjectModal(data.inject);
      setStatsRefresh((k) => k + 1);
      await fetchData();
      await fetchBlockedIps();
    } catch (e) {
      setInjectErr(e instanceof Error ? e.message : "Injection failed");
    }
  };

  const runAiAnalysis = async () => {
    setIsAnalyzing(true);
    setAnalysisError(null);
    try {
      const res = await fetch(apiUrl("/api/analyze"), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ limit: 25 }),
      });
      const data = (await res.json()) as {
        processed: number;
        source: string;
        results: AnalysisRow[];
      };
      setAnalysisReport(data);
      setStatsRefresh((k) => k + 1);
      await fetchData();
      await fetchBlockedIps();
    } catch (e) {
      setAnalysisError(e instanceof Error ? e.message : "Analysis failed");
      setAnalysisReport(null);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const confirmedCount = events.filter(
    (e) => e.classification === "confirmed_attack" || e.ground_truth_label === "attack"
  ).length;
  const stats = [
    { label: "System Health", value: "98.2%", icon: Cpu, color: "text-emerald-700" },
    { label: "Threats flagged", value: confirmedCount, icon: ShieldAlert, color: "text-orange-600" },
    { label: "Live events", value: events.length, icon: Eye, color: "text-blue-600" },
    { label: "Encryption", value: "PQC+LWE", icon: Lock, color: "text-purple-600" },
  ];

  const chartData = events.slice(0, 24).reverse().map((e) => ({
    time: new Date(e.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
    threats: e.severity === "high" || e.classification === "confirmed_attack" ? 1 : 0,
    traffic: 30 + (e.id % 40),
  }));

  const tabs: Array<{ id: typeof activeTab; label: string }> = [
    { id: "overview", label: "Overview" },
    { id: "logs", label: "Logs" },
    { id: "live", label: "Live" },
    { id: "quantum", label: "Quantum" },
    { id: "pqc", label: "PQC" },
    { id: "defense", label: "Defense" },
  ];

  return (
    <div className="min-h-screen bg-slate-50 text-slate-700 font-sans">
      <header className="border-b border-slate-200 bg-white/95 backdrop-blur-xl sticky top-0 z-50 shadow-sm">
        <div className="max-w-[1600px] mx-auto px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-emerald-500/10 rounded-xl flex items-center justify-center border border-emerald-500/20">
              <Shield className="w-6 h-6 text-emerald-700" />
            </div>
            <div>
              <h1 className="text-lg font-bold text-slate-900 tracking-tight">QuantumGuard AI</h1>
              <p className="text-[10px] uppercase tracking-[0.2em] text-slate-500 font-semibold">
                Protocol analysis · AI detection · layer-aware response
              </p>
            </div>
          </div>

          <nav className="flex items-center gap-1 flex-wrap justify-end">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`px-3 py-2 rounded-lg text-xs font-medium transition-all ${
                  activeTab === tab.id
                    ? "bg-emerald-50 text-emerald-800 border border-emerald-200 shadow-sm"
                    : "text-slate-500 hover:text-slate-800 hover:bg-slate-100 border border-transparent"
                }`}
              >
                {tab.label}
              </button>
            ))}
          </nav>

          <div className="hidden md:flex items-center gap-2 px-3 py-1.5 bg-emerald-500/10 rounded-full border border-emerald-500/20">
            <div className="w-2 h-2 bg-emerald-500 rounded-full animate-pulse" />
            <span className="text-[11px] font-bold text-emerald-700 uppercase tracking-wider">Live</span>
          </div>
        </div>
      </header>

      <main className="max-w-[1600px] mx-auto p-6 space-y-6">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {stats.map((stat, i) => (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.1 }}
              key={stat.label}
              className="bg-white border border-slate-200 p-5 rounded-2xl shadow-sm flex items-center justify-between group hover:border-slate-300 transition-colors"
            >
              <div>
                <p className="text-xs font-medium text-slate-500 uppercase tracking-wider mb-1">{stat.label}</p>
                <h3 className="text-2xl font-bold text-slate-900 tracking-tight">{stat.value}</h3>
              </div>
              <div className={`p-3 rounded-xl bg-slate-100 ${stat.color} group-hover:scale-110 transition-transform`}>
                <stat.icon className="w-6 h-6" />
              </div>
            </motion.div>
          ))}
        </div>

        {activeTab === "overview" && (
          <>
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              <div className="lg:col-span-2 bg-white border border-slate-200 rounded-2xl p-6 shadow-sm">
                <div className="flex items-center justify-between mb-8">
                  <div>
                    <h3 className="text-lg font-bold text-slate-900">Network activity</h3>
                    <p className="text-xs text-slate-500">Event timeline (recent)</p>
                    <p className="text-[10px] text-slate-400 mt-2 max-w-xl leading-relaxed">
                      These charts are <strong className="text-slate-600">dynamic</strong>: they re-render from the current event list
                      returned by <code className="text-emerald-600/90">GET /api/events</code> (threat line + traffic proxy). Refresh the
                      page or trigger Live / dataset inject to see points change.
                    </p>
                  </div>
                </div>
                <div className="h-[300px] w-full">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={chartData}>
                      <defs>
                        <linearGradient id="colorTraffic" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#10b981" stopOpacity={0.3} />
                          <stop offset="95%" stopColor="#10b981" stopOpacity={0} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke={chartGrid} vertical={false} />
                      <XAxis dataKey="time" stroke={chartAxis} fontSize={10} tickLine={false} axisLine={false} />
                      <YAxis stroke={chartAxis} fontSize={10} tickLine={false} axisLine={false} />
                      <Tooltip contentStyle={chartTooltip} itemStyle={{ fontSize: "12px", color: "#334155" }} />
                      <Area
                        type="monotone"
                        dataKey="traffic"
                        stroke="#10b981"
                        fillOpacity={1}
                        fill="url(#colorTraffic)"
                        strokeWidth={2}
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
                <div className="h-[200px] w-full mt-4">
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={chartData}>
                      <CartesianGrid strokeDasharray="3 3" stroke={chartGrid} />
                      <XAxis dataKey="time" stroke={chartAxis} fontSize={10} />
                      <YAxis stroke={chartAxis} fontSize={10} />
                      <Tooltip contentStyle={chartTooltip} />
                      <Line type="stepAfter" dataKey="threats" stroke="#f97316" strokeWidth={2} dot />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              </div>

              <div className="space-y-6">
                <div className="bg-white border border-slate-200 rounded-2xl p-6 shadow-sm">
                  <h3 className="text-lg font-bold text-slate-900 mb-2 flex items-center gap-2">
                    <Zap className="w-5 h-5 text-amber-600" />
                    Quick simulate
                  </h3>
                  <p className="text-[10px] text-slate-500 mb-3 leading-relaxed">
                    Launch a pre-scripted <strong className="text-slate-600">attack scenario</strong> into the monitoring pipeline. A
                    security event is ingested in real time with source address and threat class — the same as live production
                    traffic would appear to the analyst.
                  </p>
                  <label className="text-[10px] font-bold text-slate-500 uppercase tracking-wider block mb-1">Scenario mix</label>
                  <select
                    value={quickDataset}
                    onChange={(e) => setQuickDataset(e.target.value as typeof quickDataset)}
                    className="w-full mb-3 px-2 py-2 rounded-lg bg-white border border-slate-300 text-xs text-slate-900"
                  >
                    <option value="cicids2017">Profile A — high-volume mix</option>
                    <option value="nsl-kdd">Profile B — enterprise blend</option>
                    <option value="unsw-nb15">Profile C — wide attack surface</option>
                  </select>
                  {injectErr && (
                    <p className="text-[11px] text-red-600 mb-2 border border-red-500/30 rounded-lg px-2 py-1.5">{injectErr}</p>
                  )}
                  <div className="grid grid-cols-2 gap-3">
                    {(
                      [
                        { label: "DDoS", attackType: "ddos" },
                        { label: "Brute Force", attackType: "brute_force" },
                        { label: "SQLi", attackType: "sqli" },
                        { label: "Malware", attackType: "botnet" },
                      ] as const
                    ).map((btn) => (
                      <button
                        key={btn.label}
                        type="button"
                        onClick={() => injectDatasetAttack(btn.attackType)}
                        className="p-3 rounded-xl border border-slate-200 bg-slate-50 text-xs font-bold text-slate-600 hover:bg-red-50 hover:border-red-200 hover:text-red-700"
                      >
                        {btn.label}
                      </button>
                    ))}
                  </div>
                </div>

                <div className="bg-white border border-slate-200 rounded-2xl p-6 shadow-sm">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-lg font-bold text-slate-900 flex items-center gap-2">
                      <ShieldCheck className="w-5 h-5 text-emerald-700" />
                      AI classify
                    </h3>
                    {isAnalyzing && <RefreshCw className="w-4 h-4 text-emerald-700 animate-spin" />}
                  </div>
                  <p className="text-xs text-slate-500 mb-4">
                    Classifies pending events (Gemini when available, else heuristic). Results appear below — not only in the Live
                    stream.
                  </p>
                  <button
                    type="button"
                    onClick={runAiAnalysis}
                    disabled={isAnalyzing}
                    className="w-full py-3 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white font-bold rounded-xl flex items-center justify-center gap-2"
                  >
                    <Activity className="w-4 h-4" />
                    Run AI analysis
                  </button>
                  {analysisError && (
                    <p className="mt-3 text-xs text-red-600 border border-red-500/30 rounded-lg px-2 py-2">{analysisError}</p>
                  )}
                  {analysisReport && analysisReport.processed > 0 && (
                    <div className="mt-4 space-y-3 max-h-[340px] overflow-y-auto border border-slate-200 rounded-xl p-3 bg-slate-50">
                      <p className="text-[10px] text-slate-500">
                        Source: <span className="text-slate-600">{analysisReport.source}</span> · processed{" "}
                        {analysisReport.processed}
                      </p>
                      {analysisReport.results.map((r) => (
                        <div
                          key={r.id}
                          className="rounded-lg border border-slate-200 p-3 text-[11px] space-y-1.5 bg-slate-50"
                        >
                          <p className="font-bold text-slate-900">
                            Event #{r.id}{" "}
                            <span className="text-emerald-700 font-mono">
                              HTTP {r.httpStatus}
                            </span>{" "}
                            — {r.statusLine}
                          </p>
                          <p className="text-slate-600">
                            <span className="text-slate-500">Layer / protocol:</span>{" "}
                            <span className="text-violet-700">{r.osi_layer || "—"}</span>
                            {r.protocol && <span className="font-mono text-cyan-700"> · {r.protocol}</span>}
                            {r.severity_score != null && (
                              <span className="text-orange-700"> · score {r.severity_score}</span>
                            )}
                          </p>
                          {r.crypto_threat_class && r.crypto_threat_class !== "none" && (
                            <p className="text-slate-600">
                              <span className="text-slate-500">Threat class:</span>{" "}
                              <span
                                className={
                                  r.crypto_threat_class === "quantum_cryptographic"
                                    ? "text-purple-700"
                                    : "text-blue-700"
                                }
                              >
                                {r.crypto_threat_class.replace(/_/g, " ")}
                              </span>
                            </p>
                          )}
                          <p className="text-slate-600">
                            <span className="text-slate-500">Classification:</span> {r.classification}
                            {r.attack_type && r.attack_type !== "none" && (
                              <span className="text-orange-700"> · type: {r.attack_type}</span>
                            )}
                          </p>
                          <p className="text-slate-600">
                            <span className="text-slate-500">Confidence:</span>{" "}
                            <span className="font-mono text-cyan-700">{Math.round(r.confidence * 100)}%</span>
                          </p>
                          <p className="text-slate-600 leading-snug">{r.attackSummary}</p>
                          <p className="text-slate-500 italic">{r.reason}</p>
                          <p className="text-emerald-700/90 pt-1 border-t border-slate-200">{r.recommendation}</p>
                          {r.mitigation_hint && (
                            <p className="text-cyan-800 text-[10px]">{r.mitigation_hint}</p>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                  {analysisReport && analysisReport.processed === 0 && (
                    <p className="mt-3 text-xs text-slate-500">No pending events to analyze.</p>
                  )}
                </div>
              </div>
            </div>
            <ProtocolThreatWidget refreshKey={statsRefresh} />
            <div className="rounded-2xl border border-slate-200 bg-white shadow-sm p-6 flex flex-col md:flex-row md:items-center md:justify-between gap-4">
              <div>
                <h4 className="text-sm font-bold text-slate-900">Classical vs quantum comparison</h4>
                <p className="text-xs text-slate-500 mt-1 max-w-xl">
                  Charts and matrices live on the <strong className="text-slate-600">Defense</strong> tab; Overview stays focused on
                  activity and scenario triggers.
                </p>
              </div>
              <button
                type="button"
                onClick={() => setActiveTab("defense")}
                className="shrink-0 px-5 py-2.5 rounded-xl bg-emerald-50 hover:bg-emerald-100 text-sm font-bold text-emerald-800 border border-emerald-200"
              >
                Open Defense → comparison
              </button>
            </div>
          </>
        )}

        {activeTab === "logs" && (
          <div className="bg-white border border-slate-200 rounded-2xl overflow-hidden shadow-sm">
            <div className="p-6 border-b border-slate-200 flex items-center justify-between">
              <h3 className="text-lg font-bold text-slate-900 flex items-center gap-2">
                <Terminal className="w-5 h-5 text-blue-600" />
                Security events
              </h3>
              <button type="button" onClick={fetchData} className="p-2 hover:bg-slate-100 rounded-lg">
                <RefreshCw className="w-4 h-4 text-slate-500" />
              </button>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="bg-slate-100 text-[10px] uppercase text-slate-500">
                    <th className="p-3">Time</th>
                    <th className="p-3">IP</th>
                    <th className="p-3">Kind</th>
                    <th className="p-3">Login</th>
                    <th className="p-3">Severity</th>
                    <th className="p-3">Classification</th>
                    <th className="p-3">OSI / Proto</th>
                    <th className="p-3">Conf.</th>
                    <th className="p-3">Reason</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200">
                  <AnimatePresence mode="popLayout">
                    {events.map((e) => (
                      <motion.tr
                        layout
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        key={e.id}
                        className="hover:bg-slate-50"
                      >
                        <td className="p-3 font-mono text-slate-600 whitespace-nowrap">
                          {new Date(e.timestamp).toLocaleString()}
                        </td>
                        <td className="p-3 font-mono text-slate-900">{e.source_ip}</td>
                        <td className="p-3">{e.event_kind}</td>
                        <td className="p-3">
                          {e.action.startsWith("auth")
                            ? e.login_success === 1
                              ? "OK"
                              : "FAIL"
                            : "—"}
                        </td>
                        <td className="p-3">{e.severity}</td>
                        <td className="p-3">
                          <span
                            className={
                              e.classification === "confirmed_attack"
                                ? "text-red-600"
                                : e.classification === "suspicious"
                                  ? "text-amber-600"
                                  : e.classification === "normal"
                                    ? "text-emerald-700"
                                    : "text-slate-500"
                            }
                          >
                            {e.classification || "pending"}
                          </span>
                          {e.attack_type && e.attack_type !== "none" && (
                            <span className="block text-[10px] text-slate-500">{e.attack_type}</span>
                          )}
                        </td>
                        <td className="p-3 text-[10px]">
                          <span className="text-violet-700">{e.osi_layer || "—"}</span>
                          {e.protocol && (
                            <span className="block font-mono text-cyan-700">{e.protocol}</span>
                          )}
                          {e.mitigation_status && e.mitigation_status !== "none" && (
                            <span className="block text-emerald-700 uppercase">{e.mitigation_status}</span>
                          )}
                        </td>
                        <td className="p-3">
                          {e.confidence != null ? `${Math.round(e.confidence * 100)}%` : "—"}
                        </td>
                        <td className="p-3 text-slate-600 max-w-[220px] truncate" title={e.reason || ""}>
                          {e.reason || "—"}
                        </td>
                      </motion.tr>
                    ))}
                  </AnimatePresence>
                </tbody>
              </table>
            </div>
          </div>
        )}

        {activeTab === "live" && (
          <div className="space-y-6">
            <LoginMonitor onLoginAttempt={fetchData} />
            <RealtimePanel
              events={events}
              onEventMessage={onEventMessage}
              onEventAnalyzed={onEventAnalyzed}
              onBlockedIpUpdated={fetchBlockedIps}
            />
          </div>
        )}

        {activeTab === "quantum" && (
          <div className="space-y-6">
            <QuantumDemoPanel onComplete={() => setStatsRefresh((k) => k + 1)} />
          </div>
        )}

        {activeTab === "pqc" && (
          <div className="space-y-6">
            <PqcProtectionPanel />
            <PqcApiPanel />
          </div>
        )}

        {activeTab === "defense" && (
          <div className="space-y-6">
            <ProtocolThreatWidget refreshKey={statsRefresh} />
            <div className="bg-white border border-slate-200 rounded-2xl p-6 shadow-sm">
              <h3 className="text-lg font-bold text-slate-900 mb-2 flex items-center gap-2">
                <ShieldAlert className="w-5 h-5 text-orange-600" />
                Blocked IPs
                {blockedIps.length > 0 && (
                  <span className="text-xs font-bold px-2 py-0.5 rounded-full bg-orange-100 text-orange-700 border border-orange-200">
                    {blockedIps.length}
                  </span>
                )}
              </h3>
              <p className="text-xs text-slate-500 mb-6">
                IPs auto-blocked when AI flags suspicious activity or confirmed attacks. Run analysis or use Quick simulate to populate this list.
              </p>
              <div className="space-y-3">
                {blockedIps.length === 0 ? (
                  <p className="text-slate-500 text-sm">No blocked IPs.</p>
                ) : (
                  blockedIps.map((block) => (
                    <div
                      key={block.id}
                      className="p-4 bg-slate-100 border border-slate-200 rounded-xl flex justify-between"
                    >
                      <div className="flex items-center gap-4">
                        <Globe className="w-5 h-5 text-orange-600" />
                        <div>
                          <p className="text-sm font-bold text-slate-900 font-mono">{block.ip}</p>
                          <p className="text-[10px] text-slate-500">{block.reason}</p>
                        </div>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
            <ComparisonDashboard events={events} refreshKey={statsRefresh} />
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 rounded-2xl border border-slate-200 bg-slate-100 p-4">
              <p className="text-xs text-slate-500">
                <strong className="text-slate-600">Overview</strong> has network activity and quick attack scenarios; this tab holds
                the full comparison.
              </p>
              <button
                type="button"
                onClick={() => setActiveTab("overview")}
                className="shrink-0 py-2.5 px-5 rounded-xl bg-white hover:bg-slate-50 text-sm font-bold text-slate-800 border border-slate-300 shadow-sm"
              >
                ← Overview
              </button>
            </div>
          </div>
        )}
      </main>

      {injectModal && (
        <div
          className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-slate-900/30 backdrop-blur-sm"
          role="dialog"
          aria-modal="true"
          aria-labelledby="inject-modal-title"
        >
          <div className="relative bg-white border border-emerald-500/25 rounded-2xl max-w-lg w-full p-6 shadow-2xl">
            <button
              type="button"
              onClick={() => setInjectModal(null)}
              className="absolute top-4 right-4 p-1.5 rounded-lg hover:bg-slate-100 text-slate-600 hover:text-slate-900"
              aria-label="Close"
            >
              <X className="w-5 h-5" />
            </button>
            <h3 id="inject-modal-title" className="text-lg font-bold text-slate-900 pr-10 mb-1">
              Security event recorded
            </h3>
            <p className="text-xs text-slate-500 mb-4">
              The attack scenario was ingested into the event pipeline and is visible in Logs and live analytics.
            </p>
            <dl className="space-y-2 text-sm">
              <div className="flex justify-between gap-4 border-b border-slate-200 pb-2">
                <dt className="text-slate-500">Event reference</dt>
                <dd className="font-mono text-emerald-700">#{injectModal.id}</dd>
              </div>
              <div className="flex justify-between gap-4 border-b border-slate-200 pb-2">
                <dt className="text-slate-500">Attacker / source</dt>
                <dd className="font-mono text-slate-900">{injectModal.sourceIp}</dd>
              </div>
              <div className="flex justify-between gap-4 border-b border-slate-200 pb-2">
                <dt className="text-slate-500">Threat category</dt>
                <dd className="text-orange-700 capitalize">{injectModal.attackTypeLabel.replace(/_/g, " ")}</dd>
              </div>
              <div className="flex justify-between gap-4 border-b border-slate-200 pb-2">
                <dt className="text-slate-500">Priority</dt>
                <dd className={injectModal.groundTruth === "attack" ? "text-red-600" : "text-slate-600"}>
                  {injectModal.groundTruth === "attack" ? "Elevated — review required" : "Standard monitoring"}
                </dd>
              </div>
              <div className="pt-1">
                <dt className="text-slate-500 text-xs mb-1">Observed activity</dt>
                <dd className="text-slate-600 text-xs leading-relaxed">
                  {injectModal.description.replace(/^(Dataset replay|Application-layer signal):\s*/i, "Reported: ")}
                </dd>
              </div>
            </dl>
            <button
              type="button"
              onClick={() => setInjectModal(null)}
              className="mt-6 w-full py-2.5 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white text-sm font-bold"
            >
              OK
            </button>
          </div>
        </div>
      )}

      <footer className="max-w-[1600px] mx-auto px-6 py-8 border-t border-slate-200 mt-12">
        <div className="flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-emerald-500" />
            <span className="text-xs font-bold text-slate-900">QuantumGuard AI</span>
          </div>
          <p className="text-[10px] text-slate-500 uppercase tracking-[0.2em]">
            Real-time monitoring · Dataset replay · AI · PQC
          </p>
        </div>
      </footer>
    </div>
  );
}

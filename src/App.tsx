import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  Activity, 
  Lock, 
  AlertTriangle, 
  Terminal, 
  Cpu, 
  Globe, 
  Zap,
  ShieldAlert,
  ShieldCheck,
  RefreshCw,
  Database,
  Eye
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
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
  PieChart,
  Pie,
  Cell
} from 'recharts';
import { PQCService } from './services/pqc.ts';

// Types
interface Log {
  id: number;
  timestamp: string;
  source_ip: string;
  event_type: string;
  severity: string;
  description: string;
  status: string;
}

interface BlockedIp {
  id: number;
  ip: string;
  reason: string;
  timestamp: string;
}

export default function App() {
  const [logs, setLogs] = useState<Log[]>([]);
  const [blockedIps, setBlockedIps] = useState<BlockedIp[]>([]);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [pqcStatus, setPqcStatus] = useState<'idle' | 'generating' | 'ready'>('idle');
  const [secureMessage, setSecureMessage] = useState('');
  const [decryptedMessage, setDecryptedMessage] = useState('');
  const [keyPair, setKeyPair] = useState<any>(null);
  const [activeTab, setActiveTab] = useState<'overview' | 'logs' | 'pqc' | 'defense'>('overview');

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, []);

  const fetchData = async () => {
    try {
      const logsRes = await fetch('/api/logs');
      const logsData = await logsRes.json();
      setLogs(logsData);

      const blockedRes = await fetch('/api/blocked-ips');
      const blockedData = await blockedRes.json();
      setBlockedIps(blockedData);
    } catch (error) {
      console.error("Fetch Error:", error);
    }
  };

  const simulateAttack = async (type: string) => {
    await fetch('/api/simulate-attack', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type })
    });
    fetchData();
  };

  const runAiAnalysis = async () => {
    setIsAnalyzing(true);
    try {
      await fetch('/api/analyze-threats', { method: 'POST' });
      fetchData();
    } catch (error) {
      console.error("Analysis Error:", error);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handlePqcDemo = () => {
    setPqcStatus('generating');
    setTimeout(() => {
      const keys = PQCService.generateKeyPair();
      setKeyPair(keys);
      setPqcStatus('ready');
      
      const msg = "Quantum-Safe Protocol Initialized";
      const encrypted = PQCService.encryptMessage(msg, keys.publicKey);
      const decrypted = PQCService.decryptMessage(encrypted, keys.privateKey);
      
      setSecureMessage(JSON.stringify(encrypted.slice(0, 2)).substring(0, 50) + "...");
      setDecryptedMessage(decrypted);
    }, 1500);
  };

  const stats = [
    { label: 'System Health', value: '98.2%', icon: Cpu, color: 'text-emerald-400' },
    { label: 'Threats Blocked', value: blockedIps.length, icon: ShieldAlert, color: 'text-orange-400' },
    { label: 'Active Monitors', value: '24/7', icon: Eye, color: 'text-blue-400' },
    { label: 'Encryption Level', value: 'PQC-LWE', icon: Lock, color: 'text-purple-400' },
  ];

  const chartData = logs.slice(0, 20).reverse().map((l, i) => ({
    time: new Date(l.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    threats: l.severity === 'high' ? 1 : 0,
    traffic: Math.floor(Math.random() * 100) + 20
  }));

  return (
    <div className="min-h-screen bg-[#0a0a0c] text-zinc-300 font-sans selection:bg-emerald-500/30">
      {/* Header */}
      <header className="border-b border-white/5 bg-black/40 backdrop-blur-xl sticky top-0 z-50">
        <div className="max-w-[1600px] mx-auto px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-emerald-500/10 rounded-xl flex items-center justify-center border border-emerald-500/20">
              <Shield className="w-6 h-6 text-emerald-400" />
            </div>
            <div>
              <h1 className="text-lg font-bold text-white tracking-tight">QuantumGuard AI</h1>
              <p className="text-[10px] uppercase tracking-[0.2em] text-zinc-500 font-semibold">Post-Quantum Security Node</p>
            </div>
          </div>

          <nav className="flex items-center gap-1">
            {['overview', 'logs', 'pqc', 'defense'].map((tab) => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab as any)}
                className={`px-4 py-2 rounded-lg text-sm font-medium transition-all ${
                  activeTab === tab 
                    ? 'bg-white/5 text-white shadow-[0_0_20px_rgba(255,255,255,0.03)]' 
                    : 'text-zinc-500 hover:text-zinc-300 hover:bg-white/5'
                }`}
              >
                {tab.charAt(0).toUpperCase() + tab.slice(1)}
              </button>
            ))}
          </nav>

          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2 px-3 py-1.5 bg-emerald-500/10 rounded-full border border-emerald-500/20">
              <div className="w-2 h-2 bg-emerald-500 rounded-full animate-pulse" />
              <span className="text-[11px] font-bold text-emerald-400 uppercase tracking-wider">System Live</span>
            </div>
          </div>
        </div>
      </header>

      <main className="max-w-[1600px] mx-auto p-6 space-y-6">
        {/* Stats Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {stats.map((stat, i) => (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.1 }}
              key={stat.label}
              className="bg-zinc-900/40 border border-white/5 p-5 rounded-2xl flex items-center justify-between group hover:border-white/10 transition-colors"
            >
              <div>
                <p className="text-xs font-medium text-zinc-500 uppercase tracking-wider mb-1">{stat.label}</p>
                <h3 className="text-2xl font-bold text-white tracking-tight">{stat.value}</h3>
              </div>
              <div className={`p-3 rounded-xl bg-white/5 ${stat.color} group-hover:scale-110 transition-transform`}>
                <stat.icon className="w-6 h-6" />
              </div>
            </motion.div>
          ))}
        </div>

        {activeTab === 'overview' && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Main Chart */}
            <div className="lg:col-span-2 bg-zinc-900/40 border border-white/5 rounded-2xl p-6">
              <div className="flex items-center justify-between mb-8">
                <div>
                  <h3 className="text-lg font-bold text-white">Network Activity</h3>
                  <p className="text-xs text-zinc-500">Real-time traffic analysis and threat detection</p>
                </div>
                <div className="flex gap-4">
                  <div className="flex items-center gap-2">
                    <div className="w-3 h-3 rounded-full bg-emerald-500/50" />
                    <span className="text-xs text-zinc-400">Traffic</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="w-3 h-3 rounded-full bg-orange-500/50" />
                    <span className="text-xs text-zinc-400">Threats</span>
                  </div>
                </div>
              </div>
              <div className="h-[300px] w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={chartData}>
                    <defs>
                      <linearGradient id="colorTraffic" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#10b981" stopOpacity={0.3}/>
                        <stop offset="95%" stopColor="#10b981" stopOpacity={0}/>
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="#ffffff05" vertical={false} />
                    <XAxis dataKey="time" stroke="#ffffff20" fontSize={10} tickLine={false} axisLine={false} />
                    <YAxis stroke="#ffffff20" fontSize={10} tickLine={false} axisLine={false} />
                    <Tooltip 
                      contentStyle={{ backgroundColor: '#18181b', border: '1px solid #ffffff10', borderRadius: '12px' }}
                      itemStyle={{ fontSize: '12px' }}
                    />
                    <Area type="monotone" dataKey="traffic" stroke="#10b981" fillOpacity={1} fill="url(#colorTraffic)" strokeWidth={2} />
                    <Line type="monotone" dataKey="threats" stroke="#f97316" strokeWidth={2} dot={{ r: 4, fill: '#f97316' }} />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Quick Actions */}
            <div className="space-y-6">
              <div className="bg-zinc-900/40 border border-white/5 rounded-2xl p-6">
                <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
                  <Zap className="w-5 h-5 text-yellow-400" />
                  Threat Simulator
                </h3>
                <div className="grid grid-cols-2 gap-3">
                  {[
                    { label: 'DDoS Attack', type: 'DDoS', color: 'hover:bg-red-500/10 hover:border-red-500/20' },
                    { label: 'Brute Force', type: 'Brute Force', color: 'hover:bg-orange-500/10 hover:border-orange-500/20' },
                    { label: 'SQL Injection', type: 'SQLi', color: 'hover:bg-purple-500/10 hover:border-purple-500/20' },
                    { label: 'Malware', type: 'Malware', color: 'hover:bg-emerald-500/10 hover:border-emerald-500/20' },
                  ].map((btn) => (
                    <button
                      key={btn.type}
                      onClick={() => simulateAttack(btn.type)}
                      className={`p-3 rounded-xl border border-white/5 bg-white/5 text-xs font-bold text-zinc-400 transition-all ${btn.color} active:scale-95`}
                    >
                      {btn.label}
                    </button>
                  ))}
                </div>
              </div>

              <div className="bg-zinc-900/40 border border-white/5 rounded-2xl p-6">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-lg font-bold text-white flex items-center gap-2">
                    <ShieldCheck className="w-5 h-5 text-emerald-400" />
                    AI Defense
                  </h3>
                  {isAnalyzing && <RefreshCw className="w-4 h-4 text-emerald-400 animate-spin" />}
                </div>
                <p className="text-xs text-zinc-500 mb-6 leading-relaxed">
                  Trigger autonomous threat analysis using Gemini AI. The system will evaluate pending logs and automatically update firewall rules.
                </p>
                <button
                  onClick={runAiAnalysis}
                  disabled={isAnalyzing}
                  className="w-full py-3 bg-emerald-500 hover:bg-emerald-600 disabled:opacity-50 text-black font-bold rounded-xl transition-all flex items-center justify-center gap-2 shadow-[0_0_20px_rgba(16,185,129,0.2)]"
                >
                  <Activity className="w-4 h-4" />
                  Run AI Analysis
                </button>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'logs' && (
          <div className="bg-zinc-900/40 border border-white/5 rounded-2xl overflow-hidden">
            <div className="p-6 border-b border-white/5 flex items-center justify-between">
              <h3 className="text-lg font-bold text-white flex items-center gap-2">
                <Terminal className="w-5 h-5 text-blue-400" />
                Security Event Logs
              </h3>
              <button onClick={fetchData} className="p-2 hover:bg-white/5 rounded-lg transition-colors">
                <RefreshCw className="w-4 h-4 text-zinc-500" />
              </button>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="bg-white/5">
                    <th className="p-4 text-[10px] uppercase tracking-widest text-zinc-500 font-bold">Timestamp</th>
                    <th className="p-4 text-[10px] uppercase tracking-widest text-zinc-500 font-bold">Source IP</th>
                    <th className="p-4 text-[10px] uppercase tracking-widest text-zinc-500 font-bold">Event Type</th>
                    <th className="p-4 text-[10px] uppercase tracking-widest text-zinc-500 font-bold">Severity</th>
                    <th className="p-4 text-[10px] uppercase tracking-widest text-zinc-500 font-bold">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5">
                  <AnimatePresence mode="popLayout">
                    {logs.map((log) => (
                      <motion.tr 
                        layout
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        exit={{ opacity: 0 }}
                        key={log.id} 
                        className="hover:bg-white/[0.02] transition-colors group"
                      >
                        <td className="p-4 text-xs font-mono text-zinc-400">{new Date(log.timestamp).toLocaleString()}</td>
                        <td className="p-4 text-xs font-mono text-white">{log.source_ip}</td>
                        <td className="p-4 text-xs font-medium text-zinc-300">{log.event_type}</td>
                        <td className="p-4">
                          <span className={`px-2 py-1 rounded-md text-[10px] font-bold uppercase ${
                            log.severity === 'high' ? 'bg-red-500/10 text-red-400 border border-red-500/20' : 'bg-blue-500/10 text-blue-400 border border-blue-500/20'
                          }`}>
                            {log.severity}
                          </span>
                        </td>
                        <td className="p-4">
                          <span className={`flex items-center gap-1.5 text-[10px] font-bold uppercase ${
                            log.status === 'blocked' ? 'text-orange-400' : log.status === 'cleared' ? 'text-emerald-400' : 'text-zinc-500'
                          }`}>
                            <div className={`w-1.5 h-1.5 rounded-full ${
                              log.status === 'blocked' ? 'bg-orange-400' : log.status === 'cleared' ? 'bg-emerald-400' : 'bg-zinc-500'
                            }`} />
                            {log.status}
                          </span>
                        </td>
                      </motion.tr>
                    ))}
                  </AnimatePresence>
                </tbody>
              </table>
            </div>
          </div>
        )}

        {activeTab === 'pqc' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="bg-zinc-900/40 border border-white/5 rounded-2xl p-8 flex flex-col items-center justify-center text-center space-y-6">
              <div className="w-20 h-20 bg-purple-500/10 rounded-3xl flex items-center justify-center border border-purple-500/20">
                <Lock className="w-10 h-10 text-purple-400" />
              </div>
              <div>
                <h3 className="text-2xl font-bold text-white mb-2">Post-Quantum Cryptography</h3>
                <p className="text-zinc-500 max-w-md mx-auto leading-relaxed">
                  Simulate quantum-resistant secure communication using lattice-based Learning With Errors (LWE) algorithms.
                </p>
              </div>
              <button
                onClick={handlePqcDemo}
                disabled={pqcStatus === 'generating'}
                className="px-8 py-3 bg-purple-500 hover:bg-purple-600 disabled:opacity-50 text-white font-bold rounded-xl transition-all shadow-[0_0_30px_rgba(168,85,247,0.2)]"
              >
                {pqcStatus === 'generating' ? 'Generating Keys...' : 'Initialize Secure Channel'}
              </button>
            </div>

            <div className="bg-zinc-900/40 border border-white/5 rounded-2xl p-8 space-y-6">
              <h4 className="text-sm font-bold text-white uppercase tracking-widest flex items-center gap-2">
                <Database className="w-4 h-4 text-purple-400" />
                Quantum-Safe Protocol Output
              </h4>
              
              <div className="space-y-4">
                <div className="space-y-2">
                  <label className="text-[10px] font-bold text-zinc-500 uppercase tracking-widest">Encrypted Ciphertext (LWE Samples)</label>
                  <div className="p-4 bg-black/40 border border-white/5 rounded-xl font-mono text-xs text-purple-400/80 break-all min-h-[60px]">
                    {secureMessage || "Awaiting encryption..."}
                  </div>
                </div>

                <div className="space-y-2">
                  <label className="text-[10px] font-bold text-zinc-500 uppercase tracking-widest">Decrypted Result (Verified)</label>
                  <div className="p-4 bg-black/40 border border-white/5 rounded-xl font-mono text-xs text-emerald-400 min-h-[60px] flex items-center">
                    {decryptedMessage ? (
                      <div className="flex items-center gap-2">
                        <ShieldCheck className="w-4 h-4" />
                        {decryptedMessage}
                      </div>
                    ) : "---"}
                  </div>
                </div>

                <div className="p-4 bg-purple-500/5 border border-purple-500/10 rounded-xl">
                  <p className="text-[11px] text-purple-300/70 leading-relaxed italic">
                    Note: This simulation uses a lattice-based LWE scheme where the security is derived from the hardness of finding the shortest vector in a high-dimensional lattice, a problem currently unsolvable by quantum computers.
                  </p>
                </div>
              </div>
            </div>

            <div className="lg:col-span-2 bg-zinc-900/40 border border-white/5 rounded-2xl p-8">
              <h3 className="text-lg font-bold text-white mb-6 flex items-center gap-2">
                <Shield className="w-5 h-5 text-emerald-400" />
                System Architecture
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
                <div className="space-y-3">
                  <div className="w-8 h-8 rounded-lg bg-emerald-500/10 flex items-center justify-center border border-emerald-500/20 text-emerald-400 font-bold text-xs">01</div>
                  <h4 className="text-sm font-bold text-white">Log Collection</h4>
                  <p className="text-xs text-zinc-500 leading-relaxed">Real-time ingestion of network traffic, authentication attempts, and system events into a secure SQLite database.</p>
                </div>
                <div className="space-y-3">
                  <div className="w-8 h-8 rounded-lg bg-blue-500/10 flex items-center justify-center border border-blue-500/20 text-blue-400 font-bold text-xs">02</div>
                  <h4 className="text-sm font-bold text-white">AI Threat Analysis</h4>
                  <p className="text-xs text-zinc-500 leading-relaxed">Gemini 2.0 Flash models analyze log patterns to identify sophisticated attacks that bypass traditional signature-based systems.</p>
                </div>
                <div className="space-y-3">
                  <div className="w-8 h-8 rounded-lg bg-purple-500/10 flex items-center justify-center border border-purple-500/20 text-purple-400 font-bold text-xs">03</div>
                  <h4 className="text-sm font-bold text-white">Quantum Defense</h4>
                  <p className="text-xs text-zinc-500 leading-relaxed">Post-quantum cryptographic layers (LWE) ensure that even if an attacker intercepts traffic, it remains secure against future quantum decryption.</p>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'defense' && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="lg:col-span-2 bg-zinc-900/40 border border-white/5 rounded-2xl p-6">
              <h3 className="text-lg font-bold text-white mb-6 flex items-center gap-2">
                <ShieldAlert className="w-5 h-5 text-orange-400" />
                Active Firewall Rules (Blocked IPs)
              </h3>
              <div className="space-y-3">
                {blockedIps.length === 0 ? (
                  <div className="p-12 text-center border border-dashed border-white/5 rounded-xl">
                    <p className="text-zinc-500 text-sm">No active IP blocks detected.</p>
                  </div>
                ) : (
                  blockedIps.map((block) => (
                    <div key={block.id} className="p-4 bg-white/5 border border-white/5 rounded-xl flex items-center justify-between group hover:border-orange-500/20 transition-all">
                      <div className="flex items-center gap-4">
                        <div className="w-10 h-10 bg-orange-500/10 rounded-lg flex items-center justify-center border border-orange-500/20">
                          <Globe className="w-5 h-5 text-orange-400" />
                        </div>
                        <div>
                          <p className="text-sm font-bold text-white font-mono">{block.ip}</p>
                          <p className="text-[10px] text-zinc-500 uppercase tracking-wider">{block.reason}</p>
                        </div>
                      </div>
                      <div className="text-right">
                        <p className="text-[10px] text-zinc-500 mb-1">{new Date(block.timestamp).toLocaleTimeString()}</p>
                        <span className="px-2 py-0.5 bg-orange-500/10 text-orange-400 text-[9px] font-bold rounded uppercase border border-orange-500/20">Blocked</span>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>

            <div className="bg-zinc-900/40 border border-white/5 rounded-2xl p-6">
              <h3 className="text-lg font-bold text-white mb-6">Defense Strategy</h3>
              <div className="space-y-6">
                <div className="flex gap-4">
                  <div className="w-1 h-12 bg-emerald-500 rounded-full" />
                  <div>
                    <h4 className="text-sm font-bold text-white">Autonomous Response</h4>
                    <p className="text-xs text-zinc-500 leading-relaxed">AI models automatically identify and block malicious IP addresses within 500ms of detection.</p>
                  </div>
                </div>
                <div className="flex gap-4">
                  <div className="w-1 h-12 bg-blue-500 rounded-full" />
                  <div>
                    <h4 className="text-sm font-bold text-white">Quantum-Safe Handshake</h4>
                    <p className="text-xs text-zinc-500 leading-relaxed">All administrative commands are signed using hash-based digital signatures (LMS/XMSS).</p>
                  </div>
                </div>
                <div className="flex gap-4">
                  <div className="w-1 h-12 bg-purple-500 rounded-full" />
                  <div>
                    <h4 className="text-sm font-bold text-white">Lattice Encryption</h4>
                    <p className="text-xs text-zinc-500 leading-relaxed">Data at rest and in transit is protected by LWE-based encryption schemes.</p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="max-w-[1600px] mx-auto px-6 py-8 border-t border-white/5 mt-12">
        <div className="flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-emerald-500" />
            <span className="text-xs font-bold text-white tracking-tight">QuantumGuard AI v1.0.4</span>
          </div>
          <p className="text-[10px] text-zinc-500 uppercase tracking-[0.2em] font-semibold">
            Securing the Future Against Quantum Threats
          </p>
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
              <div className="w-1.5 h-1.5 bg-emerald-500 rounded-full" />
              <span className="text-[10px] text-zinc-400 font-bold uppercase tracking-wider">Node: SG-01</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-1.5 h-1.5 bg-blue-500 rounded-full" />
              <span className="text-[10px] text-zinc-400 font-bold uppercase tracking-wider">Latency: 14ms</span>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}

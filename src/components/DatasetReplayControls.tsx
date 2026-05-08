import React, { useState } from "react";
import { Play, Square } from "lucide-react";

export function DatasetReplayControls({ onReplayChange }: { onReplayChange: () => void }) {
  const [dataset, setDataset] = useState<"cicids2017" | "nsl-kdd" | "unsw-nb15">("cicids2017");
  const [attackType, setAttackType] = useState("any");
  const [rateMs, setRateMs] = useState(800);
  const [count, setCount] = useState(15);
  const [msg, setMsg] = useState("");

  const start = async () => {
    const res = await fetch("/api/sim/replay/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        dataset,
        attackType: attackType === "any" ? undefined : attackType,
        rateMs,
        count,
      }),
    });
    const data = (await res.json()) as { message?: string };
    setMsg(data.message || "OK");
    onReplayChange();
  };

  const stop = async () => {
    await fetch("/api/sim/replay/stop", { method: "POST" });
    setMsg("Replay stopped");
    onReplayChange();
  };

  return (
    <div className="bg-zinc-900/40 border border-white/5 rounded-2xl p-6">
      <h3 className="text-lg font-bold text-white mb-2 flex items-center gap-2">
        <Play className="w-5 h-5 text-cyan-400" />
        Dataset replay
      </h3>
      <div className="text-xs text-zinc-500 mb-4 space-y-2 leading-relaxed">
        <p>
          <strong className="text-zinc-400">What this does:</strong> reads rows from the sample CSV under{" "}
          <code className="text-cyan-500/90">datasets/samples/</code>, then inserts each row into the same{" "}
          <code className="text-cyan-500/90">events</code> table as timed application-layer traces (<code className="text-zinc-500">kind=application</code>) — same shape as a single
          injection from <strong className="text-zinc-400">Overview → Quick simulate</strong>, but replayed on an interval until
          done or stopped.
        </p>
        <p>
          Use <strong className="text-zinc-400">Start replay</strong> for continuous simulation; use Overview buttons for one-shot
          dataset rows with a confirmation popup.
        </p>
      </div>
      <div className="grid grid-cols-2 gap-3 mb-3">
        <select
          value={dataset}
          onChange={(e) => setDataset(e.target.value as typeof dataset)}
          className="px-2 py-2 rounded-lg bg-black/40 border border-white/10 text-xs text-white"
        >
          <option value="cicids2017">CICIDS2017 sample</option>
          <option value="nsl-kdd">NSL-KDD sample</option>
          <option value="unsw-nb15">UNSW-NB15 sample</option>
        </select>
        <select
          value={attackType}
          onChange={(e) => setAttackType(e.target.value)}
          className="px-2 py-2 rounded-lg bg-black/40 border border-white/10 text-xs text-white"
        >
          <option value="any">All attack-labeled rows</option>
          <option value="ddos">DDoS</option>
          <option value="brute_force">Brute force</option>
          <option value="port_scan">Port scan</option>
          <option value="botnet">Botnet</option>
          <option value="sqli">SQL injection</option>
        </select>
        <input
          type="number"
          className="px-2 py-2 rounded-lg bg-black/40 border border-white/10 text-xs text-white"
          value={rateMs}
          onChange={(e) => setRateMs(Number(e.target.value))}
        />
        <input
          type="number"
          className="px-2 py-2 rounded-lg bg-black/40 border border-white/10 text-xs text-white"
          value={count}
          onChange={(e) => setCount(Number(e.target.value))}
        />
      </div>
      <div className="flex gap-2">
        <button
          type="button"
          onClick={start}
          className="flex-1 py-2 bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-200 text-sm font-bold rounded-lg border border-cyan-500/30 flex items-center justify-center gap-2"
        >
          <Play className="w-4 h-4" /> Start replay
        </button>
        <button
          type="button"
          onClick={stop}
          className="py-2 px-4 bg-red-500/10 hover:bg-red-500/20 text-red-300 rounded-lg border border-red-500/20"
        >
          <Square className="w-4 h-4" />
        </button>
      </div>
      {msg && <p className="mt-2 text-[10px] text-zinc-500">{msg}</p>}
    </div>
  );
}

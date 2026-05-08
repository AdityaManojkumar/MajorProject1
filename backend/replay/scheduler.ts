import type { ParsedRow } from "./loaders.js";
import { loadDataset, filterAttackRows, type DatasetId } from "./loaders.js";
import { insertEvent, getDb } from "../db.js";
import { publish } from "../stream.js";

let replayTimer: ReturnType<typeof setInterval> | null = null;
let replayQueue: ParsedRow[] = [];
let replayIndex = 0;
let replayDataset = "";

export function stopReplay(): void {
  if (replayTimer) {
    clearInterval(replayTimer);
    replayTimer = null;
  }
  replayQueue = [];
  replayIndex = 0;
}

export function startReplay(
  rows: ParsedRow[],
  dataset: string,
  intervalMs: number,
  maxCount: number,
  onEvent: (id: number) => void
): { started: boolean; total: number } {
  stopReplay();
  replayDataset = dataset;
  replayQueue = rows.slice(0, maxCount);
  replayIndex = 0;
  if (replayQueue.length === 0) return { started: false, total: 0 };

  const tick = () => {
    if (replayIndex >= replayQueue.length) {
      stopReplay();
      publish({ type: "replay_complete", data: { dataset: replayDataset } });
      return;
    }
    const row = replayQueue[replayIndex++];
    const id = insertEvent({
      source_ip: row.source_ip,
      event_kind: "application",
      action: "layer7_trace",
      features_json: JSON.stringify(row.raw),
      dataset: replayDataset,
      ground_truth_label: row.ground_truth,
      severity: row.ground_truth === "attack" ? "high" : "low",
      description: row.description,
      status: "pending_analyze",
    });
    onEvent(id);
    publish({
      type: "event_created",
      data: getDb().prepare("SELECT * FROM events WHERE id = ?").get(id),
    });
  };

  tick();
  if (replayQueue.length > 1) {
    replayTimer = setInterval(tick, Math.max(200, intervalMs));
  }
  return { started: true, total: replayQueue.length };
}

/** Single-row dataset injection (same row shape as timed replay) — for Quick simulate style triggers. */
export function injectDatasetSample(
  dataset: DatasetId,
  attackType?: string
): {
  id: number;
  sourceIp: string;
  datasetId: string;
  description: string;
  attackTypeLabel: string;
  groundTruth: string;
} | null {
  const all = loadDataset(dataset);
  if (all.length === 0) return null;
  const rows = filterAttackRows(all, attackType && attackType !== "any" ? attackType : undefined);
  const pool = rows.length > 0 ? rows : all;
  const row = pool[Math.floor(Math.random() * pool.length)]!;
  const id = insertEvent({
    source_ip: row.source_ip,
    event_kind: "application",
    action: "layer7_trace",
    features_json: JSON.stringify(row.raw),
    dataset,
    ground_truth_label: row.ground_truth,
    severity: row.ground_truth === "attack" ? "high" : "low",
    description: row.description,
    status: "pending_analyze",
  });
  const full = getDb().prepare("SELECT * FROM events WHERE id = ?").get(id);
  publish({ type: "event_created", data: full });
  return {
    id,
    sourceIp: row.source_ip,
    datasetId: dataset,
    description: row.description,
    attackTypeLabel: row.attack_type,
    groundTruth: row.ground_truth,
  };
}

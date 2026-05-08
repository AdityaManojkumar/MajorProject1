import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const SAMPLES_DIR = path.join(__dirname, "../../datasets/samples");

export type DatasetId = "cicids2017" | "nsl-kdd" | "unsw-nb15";

export interface ParsedRow {
  source_ip: string;
  description: string;
  ground_truth: "normal" | "attack";
  attack_type: string;
  raw: Record<string, string>;
}

function parseCsvLine(line: string): string[] {
  const out: string[] = [];
  let cur = "";
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c === '"') {
      inQuotes = !inQuotes;
    } else if ((c === "," && !inQuotes) || c === "\r") {
      out.push(cur.trim());
      cur = "";
    } else {
      cur += c;
    }
  }
  out.push(cur.trim());
  return out;
}

function loadCsv(filePath: string): ParsedRow[] {
  if (!fs.existsSync(filePath)) return [];
  const text = fs.readFileSync(filePath, "utf8");
  const lines = text.split("\n").filter((l) => l.trim());
  if (lines.length < 2) return [];
  const header = parseCsvLine(lines[0]).map((h) => h.toLowerCase().replace(/\s/g, "_"));
  const rows: ParsedRow[] = [];
  for (let i = 1; i < lines.length; i++) {
    const cells = parseCsvLine(lines[i]);
    const raw: Record<string, string> = {};
    header.forEach((h, j) => {
      raw[h] = cells[j] ?? "";
    });
    rows.push(mapRow(raw));
  }
  return rows;
}

function mapRow(raw: Record<string, string>): ParsedRow {
  const ip =
    raw.source_ip ||
    raw.srcip ||
    raw["source_ip"] ||
    raw["src_ip"] ||
    raw["srcip"] ||
    "10.0.0.1";
  const label = (raw.label || raw.attack_cat || raw.category || raw["label"] || "normal").toLowerCase();
  const isAttack =
    label.includes("attack") ||
    label.includes("anomaly") ||
    label.includes("dos") ||
    label.includes("ddos") ||
    label.includes("brute") ||
    label.includes("scan") ||
    label.includes("botnet") ||
    label.includes("exploit") ||
    label.includes("injection") ||
    label.includes("fuzz") ||
    label.includes("reconnaissance") ||
    label === "1";
  const attackType = inferAttackType(raw, label);
  const desc = buildDescription(raw, attackType);
  return {
    source_ip: ip,
    description: desc,
    ground_truth: isAttack ? "attack" : "normal",
    attack_type: attackType,
    raw,
  };
}

function inferAttackType(raw: Record<string, string>, label: string): string {
  const l = label + " " + JSON.stringify(raw).toLowerCase();
  if (l.includes("ddos") || l.includes("dos")) return "ddos";
  if (l.includes("brute") || l.includes("ftp") && l.includes("patator")) return "brute_force";
  if (l.includes("scan") || l.includes("port")) return "port_scan";
  if (l.includes("botnet")) return "botnet";
  if (l.includes("sql") || l.includes("injection")) return "sqli";
  return "unknown";
}

function buildDescription(raw: Record<string, string>, attackType: string): string {
  const proto = raw.protocol || raw.proto || "";
  const port = raw.destination_port || raw.dstport || raw.dport || "";
  return `Application-layer signal: ${attackType}${proto ? ` proto=${proto}` : ""}${port ? ` port=${port}` : ""}`;
}

export function loadDataset(dataset: DatasetId): ParsedRow[] {
  const files: Record<DatasetId, string> = {
    cicids2017: path.join(SAMPLES_DIR, "cicids2017_sample.csv"),
    "nsl-kdd": path.join(SAMPLES_DIR, "nsl-kdd_sample.csv"),
    "unsw-nb15": path.join(SAMPLES_DIR, "unsw-nb15_sample.csv"),
  };
  return loadCsv(files[dataset]);
}

export function filterAttackRows(rows: ParsedRow[], attackType?: string): ParsedRow[] {
  let r = rows.filter((x) => x.ground_truth === "attack");
  if (attackType && attackType !== "any") {
    const at = attackType.toLowerCase().replace(/ /g, "_");
    r = r.filter((x) => x.attack_type === at || x.description.toLowerCase().includes(at));
  }
  return r.length ? r : rows;
}

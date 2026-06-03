/**
 * Event pipeline: Protocol Analysis Layer runs between ingestion and AI classification.
 */
import { getEventById, updateEventProtocolAnalysis } from "./db.js";
import { analyzeProtocolTraffic } from "./protocol/analyzer.js";
import type { SecurityEventRow } from "./types.js";

/** Run protocol analysis on a newly ingested event and persist L3/L4/L7 features. */
export function processEventThroughProtocolLayer(eventId: number): SecurityEventRow | undefined {
  const row = getEventById(eventId);
  if (!row) return undefined;

  const analysis = analyzeProtocolTraffic(row);
  updateEventProtocolAnalysis(eventId, {
    osi_layer: analysis.primaryOsiLayer,
    protocol: analysis.detectedProtocol,
    protocol_analysis_json: JSON.stringify(analysis),
  });

  return getEventById(eventId);
}

/** Re-analyze protocol features for a batch (e.g. before AI classify). */
export function refreshProtocolAnalysis(events: SecurityEventRow[]): SecurityEventRow[] {
  return events.map((e) => {
    processEventThroughProtocolLayer(e.id);
    return getEventById(e.id) ?? e;
  });
}

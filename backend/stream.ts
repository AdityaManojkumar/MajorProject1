import type { Response } from "express";

export type StreamMessage = {
  type: string;
  data?: unknown;
};

const clients = new Set<Response>();

export function addSseClient(res: Response): void {
  clients.add(res);
}

export function removeSseClient(res: Response): void {
  clients.delete(res);
}

export function publish(msg: StreamMessage): void {
  const line = `data: ${JSON.stringify(msg)}\n\n`;
  for (const res of clients) {
    try {
      res.write(line);
    } catch {
      clients.delete(res);
    }
  }
}

export function sseClientCount(): number {
  return clients.size;
}

/**
 * An append-only JSONL file whose rows are hash-chained: each row carries
 * `prev` (the hash of the row before it, "" for the first) and `hash`
 * (SHA-256 over prev + the row's own fields). Editing, dropping or
 * reordering any row breaks every hash after it, so `verify` finds
 * tampering; nothing here stops it. The audit ledger is built on it, and
 * any other ledger an app keeps can be.
 */
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { appendFile, chmod, mkdir } from "node:fs/promises";
import { dirname } from "node:path";
import { createInterface } from "node:readline";
import { tailJson } from "./tail.js";

export interface Chained {
  prev: string;
  hash: string;
}

/** Hash of one row: `prev`, then the row's fields in key order, so the value is stable however it was built. */
export function rowHash(prev: string, row: object): string {
  const fields = row as Record<string, unknown>;
  const keys = Object.keys(fields)
    .filter((k) => k !== "prev" && k !== "hash")
    .sort();
  const h = createHash("sha256").update(prev);
  for (const k of keys) h.update("\0").update(k).update("=").update(JSON.stringify(fields[k]));
  return h.digest("hex");
}

export interface ChainedFile<T extends object> {
  /** Appends the row with its chain fields; one writer per process (appends are serialized here). */
  append(row: T): Promise<T & Chained>;
  /** Newest last; the chain fields come along. */
  recent(n?: number): Promise<(T & Chained)[]>;
}

/**
 * The whole file checked: `brokenAt` is the first row (0-based) whose hash
 * or prev does not fit. Rows written before chaining (no `hash`) may only
 * lead the file; they are counted in `unchained`, never verified.
 */
export interface Verification {
  rows: number;
  unchained: number;
  ok: boolean;
  brokenAt: number | null;
}

export function chainedFile<T extends object>(path: string): ChainedFile<T> {
  let ready: Promise<string> | null = null;
  /** The last hash; read once from the file's tail, then carried in memory. */
  let tip = "";
  let queue: Promise<unknown> = Promise.resolve();
  const ensure = () =>
    (ready ??= (async () => {
      await mkdir(dirname(path), { recursive: true, mode: 0o700 });
      await appendFile(path, "", { mode: 0o600 });
      await chmod(path, 0o600);
      const [last] = await tailJson<Partial<Chained>>(path, 1);
      // A file from before chaining: the first chained row binds every old line, so nothing
      // can be slipped in front of the chain later. Read whole once, here only.
      tip = typeof last?.hash === "string" ? last.hash : last ? await prefixHash(path) : "";
      return tip;
    })());
  return {
    append(row) {
      const next = queue.then(async () => {
        await ensure();
        const chained = { ...row, prev: tip, hash: rowHash(tip, row) };
        await appendFile(path, `${JSON.stringify(chained)}\n`, { mode: 0o600 });
        tip = chained.hash;
        return chained;
      });
      queue = next.catch(() => undefined);
      return next;
    },
    async recent(n = 50) {
      return tailJson<T & Chained>(path, n);
    },
  };
}

async function openLines(path: string): Promise<AsyncIterable<string> | null> {
  try {
    const stream = createReadStream(path, { encoding: "utf8" });
    await new Promise<void>((ok, no) => stream.once("open", () => ok()).once("error", no));
    return createInterface({ input: stream, crlfDelay: Infinity });
  } catch {
    return null;
  }
}

/** SHA-256 over the file's unchained lines, in order: what the first chained row's `prev` carries. */
async function prefixHash(path: string): Promise<string> {
  const lines = await openLines(path);
  const h = createHash("sha256");
  if (lines) for await (const line of lines) if (line) h.update(line).update("\n");
  return h.digest("hex");
}

/** Walk every row from the start. */
export async function verifyChain(path: string): Promise<Verification> {
  const lines = await openLines(path);
  if (!lines) return { rows: 0, unchained: 0, ok: true, brokenAt: null };
  let prev = "";
  let rows = 0;
  let unchained = 0;
  let brokenAt: number | null = null;
  const prefix = createHash("sha256");
  // Streamed line by line: a ledger is read from the end everywhere else, whole only here.
  for await (const line of lines) {
    if (!line) continue;
    const i = rows++;
    if (brokenAt !== null) continue;
    let row: Record<string, unknown>;
    try {
      row = JSON.parse(line) as Record<string, unknown>;
    } catch {
      brokenAt = i;
      continue;
    }
    if (!("hash" in row) && unchained === i) {
      unchained++;
      prefix.update(line).update("\n");
      continue;
    }
    if (i === unchained && unchained > 0) prev = prefix.digest("hex");
    if (row.prev !== prev || row.hash !== rowHash(prev, row)) brokenAt = i;
    else prev = row.hash as string;
  }
  return { rows, unchained, ok: brokenAt === null, brokenAt };
}

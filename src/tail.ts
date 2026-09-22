/**
 * The last lines of an append-only file, read from its end in blocks: a
 * ledger that grows for months costs the same to consult as a fresh one.
 */
import { open } from "node:fs/promises";

const BLOCK = 64 * 1024;

/** The last `n` non-empty lines of `path`, oldest first; [] for a missing file. */
export async function tailLines(path: string, n: number): Promise<string[]> {
  if (n <= 0) return [];
  let fh: Awaited<ReturnType<typeof open>>;
  try {
    fh = await open(path, "r");
  } catch {
    return [];
  }
  try {
    const { size } = await fh.stat();
    const chunks: Buffer[] = [];
    let pos = size;
    let newlines = 0;
    // Stop once the read-back text holds n+1 line breaks: the first partial line is then cut whole.
    while (pos > 0 && newlines <= n) {
      const len = Math.min(BLOCK, pos);
      pos -= len;
      const buf = Buffer.alloc(len);
      await fh.read(buf, 0, len, pos);
      chunks.unshift(buf);
      for (let i = 0; i < len; i++) if (buf[i] === 10) newlines++;
    }
    // With n+1 line breaks in hand the last n lines are whole; the window's first line may be a
    // fragment and is the one `slice(-n)` leaves behind.
    const lines = Buffer.concat(chunks).toString("utf8").split("\n").filter(Boolean);
    return lines.slice(-n);
  } finally {
    await fh.close();
  }
}

/** Each of the last `n` lines parsed as JSON; a torn line is skipped. */
export async function tailJson<T>(path: string, n: number): Promise<T[]> {
  const out: T[] = [];
  for (const l of await tailLines(path, n)) {
    try {
      out.push(JSON.parse(l) as T);
    } catch {
      // a line still being written, or a fragment at the window's start
    }
  }
  return out;
}

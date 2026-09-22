import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { chainedFile, rowHash, verifyChain } from "./chain.js";

const fresh = async () => join(await mkdtemp(join(tmpdir(), "chain-")), "l.jsonl");

describe("chained ledger", () => {
  it("links each row to the one before and verifies clean", async () => {
    const path = await fresh();
    const f = chainedFile<{ n: number; who: string }>(path);
    const [a, b] = await Promise.all([f.append({ n: 1, who: "x" }), f.append({ n: 2, who: "y" })]);
    expect(a.prev).toBe("");
    expect(b.prev).toBe(a.hash);
    expect(b.hash).toBe(rowHash(a.hash, { n: 2, who: "y" }));
    expect(await verifyChain(path)).toEqual({ rows: 2, unchained: 0, ok: true, brokenAt: null });
    // A new process picks the tip up from the file.
    const c = await chainedFile<{ n: number }>(path).append({ n: 3 });
    expect(c.prev).toBe(b.hash);
    expect((await f.recent(2)).map((r) => r.n)).toEqual([2, 3]);
  });

  it("hashes are stable under key order", () => {
    expect(rowHash("p", { a: 1, b: "x" })).toBe(rowHash("p", { b: "x", a: 1 }));
    expect(rowHash("p", { a: 1 })).not.toBe(rowHash("q", { a: 1 }));
  });

  it("an edited, dropped or inserted row is found", async () => {
    const path = await fresh();
    const f = chainedFile<{ n: number }>(path);
    for (const n of [1, 2, 3]) await f.append({ n });
    const lines = (await readFile(path, "utf8")).trim().split("\n");
    const edited = lines.map((l, i) => (i === 1 ? l.replace('"n":2', '"n":9') : l));
    await writeFile(path, `${edited.join("\n")}\n`);
    expect(await verifyChain(path)).toMatchObject({ rows: 3, ok: false, brokenAt: 1 });
    await writeFile(path, `${[lines[0], lines[2]].join("\n")}\n`);
    expect(await verifyChain(path)).toMatchObject({ rows: 2, ok: false, brokenAt: 1 });
    await writeFile(path, `${JSON.stringify({ n: 0 })}\n${lines.join("\n")}\n`);
    // Nothing slips in front either: the first row's prev is "" and the prefix would not be.
    expect(await verifyChain(path)).toMatchObject({ rows: 4, ok: false, brokenAt: 1 });
  });

  it("a missing file is an empty, intact chain", async () => {
    expect(await verifyChain(join(await fresh(), "none"))).toEqual({
      rows: 0,
      unchained: 0,
      ok: true,
      brokenAt: null,
    });
  });

  it("a file from before chaining is bound by the first chained row", async () => {
    const path = await fresh();
    const old = [JSON.stringify({ old: 1 }), JSON.stringify({ old: 2 })];
    await writeFile(path, `${old.join("\n")}\n`);
    await chainedFile<{ n: number }>(path).append({ n: 1 });
    expect(await verifyChain(path)).toEqual({ rows: 3, unchained: 2, ok: true, brokenAt: null });
    const chained = (await readFile(path, "utf8")).trim().split("\n")[2] as string;
    // Insert, edit or prepend an old line: the prefix hash no longer matches.
    await writeFile(path, `${JSON.stringify({ old: 0 })}\n${old.join("\n")}\n${chained}\n`);
    expect(await verifyChain(path)).toMatchObject({ rows: 4, ok: false, brokenAt: 3 });
    await writeFile(path, `${old[0]}\n${chained}\n`);
    expect(await verifyChain(path)).toMatchObject({ rows: 2, ok: false, brokenAt: 1 });
    // An unchained row after the chain began is an insertion.
    await writeFile(path, `${old.join("\n")}\n${chained}\n${JSON.stringify({ old: 3 })}\n`);
    expect(await verifyChain(path)).toMatchObject({ rows: 4, ok: false, brokenAt: 3 });
  });
});

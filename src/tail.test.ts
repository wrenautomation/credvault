import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { tailJson, tailLines } from "./tail.js";

describe("tail reads", () => {
  it("reads the last n lines from the file's end across block edges; a torn last line is skipped as JSON", async () => {
    const dir = mkdtempSync(join(tmpdir(), "credkeep-tail-"));
    const file = join(dir, "a.jsonl");
    // ~1.5 MB: many 64 KB blocks, so the window starts mid-line.
    const lines = Array.from({ length: 30_000 }, (_, i) =>
      JSON.stringify({ i, pad: "x".repeat(40) }),
    );
    writeFileSync(file, `${lines.join("\n")}\n`);
    const got = await tailLines(file, 3);
    expect(got).toEqual(lines.slice(-3));
    expect((await tailLines(file, 5_000)).length).toBe(5_000);
    expect(await tailLines(file, 100_000)).toHaveLength(30_000);
    expect(await tailLines(join(dir, "missing"), 3)).toEqual([]);
    writeFileSync(file, `${lines.slice(0, 2).join("\n")}\n{"i":`);
    expect((await tailJson<{ i: number }>(file, 5)).map((r) => r.i)).toEqual([0, 1]);
  });
});

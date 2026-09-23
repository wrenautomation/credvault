import { mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  DeleteParameterCommand,
  DescribeParametersCommand,
  GetParameterCommand,
  GetParametersByPathCommand,
  PutParameterCommand,
  type SSMClient,
} from "@aws-sdk/client-ssm";
import { describe, expect, it } from "vitest";
import {
  envFileStore,
  expiring,
  memoryEnvStore,
  parseDotenv,
  ssmEnvStore,
  syncedEnvStore,
  toDotenv,
  toExports,
  upsertDotenv,
} from "./env-store.js";

describe("dotenv helpers", () => {
  it("parses as a shell would, inlines a JSON file a value names, and renders back", () => {
    const text = `# comment
export A=1
B="two words" # trailing
C='x'
SA=/tmp/sa.json
bad-name=1
EMPTY=
`;
    const entries = parseDotenv(text, (p) => (p === "/tmp/sa.json" ? '{"k":1}' : null));
    expect(entries).toEqual([
      { name: "A", value: "1" },
      { name: "B", value: "two words" },
      { name: "C", value: "x" },
      { name: "SA", value: '{"k":1}' },
    ]);
    expect(toExports([{ name: "P", value: "it's" }])).toBe("export P='it'\\''s'\n");
    expect(toDotenv([{ name: "A", value: "1" }])).toBe("A=1\n");
    expect(toDotenv([{ name: "SA", value: "{\n}" }], (n) => `/x/${n.toLowerCase()}.json`)).toBe(
      "SA=/x/sa.json\n",
    );
    expect(() => toDotenv([{ name: "SA", value: "{\n}" }])).toThrow(/spans lines/);
    expect(
      upsertDotenv("A=old\nKEEP=1\n", [
        { name: "A", value: "new" },
        { name: "Z", value: "9" },
      ]),
    ).toBe("A=new\nKEEP=1\nZ=9\n");
  });
});

describe("expiry", () => {
  it("is kept with the value, cleared by a put without one, and listed soonest first", async () => {
    const store = memoryEnvStore();
    await store.put("NPM_TOKEN", "t", { expiresAt: "2026-12-21T00:00:00Z" });
    await store.put("LINKEDIN_TOKEN", "l", { expiresAt: "2026-10-15T00:00:00.000Z" });
    await store.put("STATIC_KEY", "k");
    const listed = await store.list();
    expect(listed.map((e) => [e.name, e.expiresAt])).toEqual([
      ["LINKEDIN_TOKEN", "2026-10-15T00:00:00.000Z"],
      ["NPM_TOKEN", "2026-12-21T00:00:00.000Z"],
      ["STATIC_KEY", null],
    ]);
    const now = Date.parse("2026-09-22T00:00:00Z");
    const day = 86_400_000;
    expect(expiring(listed, 14 * day, now)).toEqual([]);
    expect(expiring(listed, 30 * day, now).map((e) => e.name)).toEqual(["LINKEDIN_TOKEN"]);
    expect(expiring(listed, 100 * day, now).map((e) => e.name)).toEqual([
      "LINKEDIN_TOKEN",
      "NPM_TOKEN",
    ]);
    await store.put("NPM_TOKEN", "t2");
    expect((await store.list()).find((e) => e.name === "NPM_TOKEN")?.expiresAt).toBeNull();
  });
});

describe("ssm store", () => {
  /** SSM as a map, speaking the five commands the store sends. */
  const fakeSsm = () => {
    const params = new Map<string, { value: string; description: string }>();
    const sent: string[] = [];
    const send = async (cmd: unknown) => {
      sent.push((cmd as object).constructor.name);
      const input = (cmd as { input: Record<string, unknown> }).input;
      if (cmd instanceof PutParameterCommand) {
        params.set(input.Name as string, {
          value: input.Value as string,
          description: input.Description as string,
        });
        return {};
      }
      if (cmd instanceof DescribeParametersCommand)
        return {
          Parameters: [...params].map(([Name, p]) => ({ Name, Description: p.description })),
        };
      if (cmd instanceof GetParametersByPathCommand)
        return { Parameters: [...params].map(([Name, p]) => ({ Name, Value: p.value })) };
      if (cmd instanceof GetParameterCommand)
        return { Parameter: { Value: params.get(input.Name as string)?.value } };
      if (cmd instanceof DeleteParameterCommand) {
        params.delete(input.Name as string);
        return {};
      }
      throw new Error("unexpected command");
    };
    return { ssm: { send } as unknown as SSMClient, params, sent };
  };

  it("lists names and expiry without decrypting, and reads values only on all/get", async () => {
    const f = fakeSsm();
    const store = ssmEnvStore(f.ssm, "/app/config");
    await store.put("TOKEN", "secret", { expiresAt: "2026-12-21T00:00:00Z" });
    await store.put("KEY", "k");
    expect(f.params.get("/app/config/TOKEN")?.description).toBe("expires 2026-12-21T00:00:00.000Z");
    expect(f.params.get("/app/config/KEY")?.description).toBe("no expiry");
    f.sent.length = 0;
    const listed = await store.list();
    expect(listed.map((e) => [e.name, e.expiresAt])).toEqual([
      ["KEY", null],
      ["TOKEN", "2026-12-21T00:00:00.000Z"],
    ]);
    expect(JSON.stringify(listed)).not.toContain("secret");
    expect(f.sent).toEqual(["DescribeParametersCommand"]);
    expect(await store.all()).toEqual([
      { name: "KEY", value: "k" },
      { name: "TOKEN", value: "secret" },
    ]);
    expect(await store.get("TOKEN")).toBe("secret");
    await expect(store.put("bad-name", "x")).rejects.toThrow(/bad name/);
  });

  it("lists once for back-to-back readers, fresh again after a write", async () => {
    const f = fakeSsm();
    const store = ssmEnvStore(f.ssm, "/app/config");
    await store.put("A", "1");
    f.sent.length = 0;
    await Promise.all([store.list(), store.list()]);
    await store.list();
    expect(f.sent).toEqual(["DescribeParametersCommand"]);
    await store.put("B", "2");
    expect((await store.list()).map((e) => e.name)).toEqual(["A", "B"]);
    expect(f.sent.filter((c) => c === "DescribeParametersCommand")).toHaveLength(2);
  });
});

describe("env file store", () => {
  it("keeps other lines, writes 0600, and records expiry as a comment above the line", async () => {
    const file = join(mkdtempSync(join(tmpdir(), "credvault-")), ".env");
    writeFileSync(file, "# mine\nKEEP=1\nTOKEN=old\n");
    const env: NodeJS.ProcessEnv = {};
    const store = envFileStore(file, env);
    await store.put("TOKEN", "new", { expiresAt: "2026-12-21T00:00:00Z" });
    expect(readFileSync(file, "utf8")).toBe(
      "# mine\nKEEP=1\n# TOKEN expires 2026-12-21T00:00:00.000Z\nTOKEN=new\n",
    );
    expect(statSync(file).mode & 0o777).toBe(0o600);
    expect(env.TOKEN).toBe("new");
    expect(await store.list()).toEqual([
      { name: "KEEP", updatedAt: null, expiresAt: null },
      { name: "TOKEN", updatedAt: null, expiresAt: "2026-12-21T00:00:00.000Z" },
    ]);
    // A put with no expiry clears the old one, as SSM's does.
    await store.put("TOKEN", "newer");
    expect(readFileSync(file, "utf8")).toBe("# mine\nKEEP=1\nTOKEN=newer\n");
    expect(await store.get("TOKEN")).toBe("newer");
    expect(await store.remove("TOKEN")).toBe(true);
    expect(await store.remove("TOKEN")).toBe(false);
    expect(await store.all()).toEqual([{ name: "KEEP", value: "1" }]);
    await expect(store.put("T", "a\nb")).rejects.toThrow(/spans lines/);
  });
});

describe("synced env store", () => {
  it("a mint lands on both, reads prefer the local copy, and a refused shared write is loud", async () => {
    const local = memoryEnvStore({ ONLY_HERE: "l" });
    const shared = memoryEnvStore({ ONLY_THERE: "s", BOTH: "old" });
    const store = syncedEnvStore(local, shared);
    await store.put("BOTH", "new", { expiresAt: "2026-11-21T00:00:00.000Z" });
    expect(shared.values.BOTH).toBe("new");
    expect(await store.get("ONLY_THERE")).toBe("s");
    expect(await store.getMany(["ONLY_HERE", "ONLY_THERE", "NONE"])).toEqual({
      ONLY_HERE: "l",
      ONLY_THERE: "s",
    });
    expect((await store.list()).map((e) => [e.name, e.expiresAt])).toEqual([
      ["BOTH", "2026-11-21T00:00:00.000Z"],
      ["ONLY_HERE", null],
      ["ONLY_THERE", null],
    ]);
    const down = { ...shared, put: async () => Promise.reject(new Error("offline")) };
    await expect(syncedEnvStore(local, down).put("MINTED", "t")).rejects.toThrow(
      /MINTED kept on this machine only/,
    );
    expect(local.values.MINTED).toBe("t");
    expect(await store.remove("BOTH")).toBe(true);
    expect(shared.values.BOTH).toBeUndefined();
  });
});

import { mkdtempSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  credentialEnv,
  envCredentials,
  fileCredentials,
  layeredCredentials,
  memoryCredentials,
  pullCredentials,
  pushCredentials,
} from "./credentials.js";

const RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

describe("credentials", () => {
  it("file store writes 0600, round-trips, and lists names only", async () => {
    const dir = mkdtempSync(join(tmpdir(), "credkeep-"));
    const store = fileCredentials(join(dir, "c.json"));
    await store.put("cloudflare", { username: "u", password: "p", totpSecret: RFC_SECRET });
    expect(statSync(join(dir, "c.json")).mode & 0o777).toBe(0o600);
    expect(await store.list()).toEqual(["cloudflare"]);
    expect((await store.get("cloudflare"))?.totpSecret).toBe(RFC_SECRET);
    expect(await store.get("nope")).toBeNull();
  });
  it("env store reads CRED_* and is read-only", async () => {
    const env = {
      CRED_GOOGLE_ADMIN_USERNAME: "a@b.co",
      CRED_GOOGLE_ADMIN_PASSWORD: "pw",
    };
    const store = envCredentials(env);
    expect(await store.list()).toEqual(["google-admin"]);
    expect((await store.get("google-admin"))?.username).toBe("a@b.co");
    await expect(store.put("x", { username: "u", password: "p" })).rejects.toThrow(/read-only/);
  });
  it("a credential round-trips through env entries, via-only included", async () => {
    const entries = credentialEnv("my-site", {
      username: "w@wren.co",
      via: "google",
      codesInbox: "codes@wren.co",
      recoveryCodes: [],
      passkeys: [],
    });
    expect(entries.map((e) => e.name)).toEqual([
      "CRED_MY_SITE_USERNAME",
      "CRED_MY_SITE_VIA",
      "CRED_MY_SITE_CODES_INBOX",
    ]);
    const env = Object.fromEntries(entries.map((e) => [e.name, e.value]));
    const back = await envCredentials(env).get("my-site");
    expect(back?.via).toBe("google");
    expect(back?.codesInbox).toBe("codes@wren.co");
    expect(back?.password).toBeUndefined();
  });
  it("an account keeps its own mark in the env name and comes back as itself", async () => {
    const entries = credentialEnv("google@ops", {
      username: "o@x.co",
      password: "p",
      recoveryCodes: [],
      passkeys: [],
    });
    expect(entries[0]?.name).toBe("CRED_GOOGLE__OPS_USERNAME");
    const env = Object.fromEntries(entries.map((e) => [e.name, e.value]));
    expect(await envCredentials(env).list()).toEqual(["google@ops"]);
    expect((await envCredentials(env).get("google@ops"))?.username).toBe("o@x.co");
  });
  it("push sends every site but canaries; pull keeps what is here unless told, and never drops passkeys", async () => {
    const local = memoryCredentials({
      a: { username: "a", password: "1", totpSecret: "JBSWY3DPEHPK3PXP" },
      "b@two": { username: "b", via: "google" },
      stripe: { username: "bait", password: "x", canary: true },
    });
    const kv = new Map<string, string>();
    const store = {
      all: async () => [...kv].map(([name, value]) => ({ name, value })),
      put: async (name: string, value: string) => void kv.set(name, value),
    };
    const pushed = await pushCredentials(local, store);
    expect(pushed.map((p) => p.site)).toEqual(["a", "b@two"]);
    expect([...kv.keys()]).toEqual([
      "CRED_A_USERNAME",
      "CRED_A_PASSWORD",
      "CRED_A_TOTP_SECRET",
      "CRED_B__TWO_USERNAME",
      "CRED_B__TWO_VIA",
    ]);
    const other = memoryCredentials({
      a: {
        username: "old",
        password: "old",
        passkeys: [
          {
            rpId: "a",
            credentialId: "k",
            privateKey: "d",
            signCount: 0,
            isResidentCredential: true,
          },
        ],
      },
    });
    const first = await pullCredentials(store, other);
    expect(first).toEqual({ written: ["b@two"], kept: ["a"] });
    expect((await other.get("a"))?.password).toBe("old");
    const second = await pullCredentials(store, other, ["a"], { overwrite: true });
    expect(second).toEqual({ written: ["a"], kept: [] });
    const a = await other.get("a");
    expect(a?.password).toBe("1");
    expect(a?.passkeys).toHaveLength(1);
    await expect(pullCredentials(store, other, ["nope"])).rejects.toThrow(/push it first/);
  });
  it("layered: first hit wins, writes go to the first store", async () => {
    const a = memoryCredentials({ s: { username: "a", password: "1" } });
    const b = memoryCredentials({
      s: { username: "b", password: "2" },
      t: { username: "t", password: "3" },
    });
    const l = layeredCredentials([a, b], a);
    expect((await l.get("s"))?.username).toBe("a");
    expect((await l.get("t"))?.username).toBe("t");
    await l.put("n", { username: "n", password: "4" });
    expect(await a.list()).toContain("n");
  });
});

describe("credential schema", () => {
  it("takes a via credential without a password, and nothing without either", async () => {
    const store = memoryCredentials();
    await store.put("s", { username: "u", via: "google", url: "https://s.test/login" });
    expect((await store.get("s"))?.password).toBeUndefined();
    await expect(store.put("t", { username: "u" })).rejects.toThrow(/password or a via/);
  });
  it("normalizes a spaced seed and rejects a 6-digit code", async () => {
    const store = memoryCredentials();
    await store.put("s", { username: "u", password: "p", totpSecret: "jbsw y3dp-ehpk 3pxp" });
    expect((await store.get("s"))?.totpSecret).toBe("JBSWY3DPEHPK3PXP");
    await expect(
      store.put("s", { username: "u", password: "p", totpSecret: "123456" }),
    ).rejects.toThrow(/base32 seed/);
  });
});

describe("sealed credential file", () => {
  it("writes ciphertext, reads it back, and upgrades a plain file on the next write", async () => {
    const { aesGcmCipher, isSealed } = await import("./cipher.js");
    const { readFileSync, writeFileSync } = await import("node:fs");
    const dir = mkdtempSync(join(tmpdir(), "credkeep-sealed-"));
    const file = join(dir, "c.json");
    const key = Buffer.alloc(32, 7);
    writeFileSync(
      file,
      JSON.stringify({ sites: { old: { username: "o", password: "p", recoveryCodes: [] } } }),
    );
    const store = fileCredentials(file, aesGcmCipher(key));
    expect((await store.get("old"))?.username).toBe("o");
    await store.put("new", { username: "n", password: "q" });
    const raw = readFileSync(file, "utf8");
    expect(isSealed(raw)).toBe(true);
    expect(raw).not.toContain("password");
    expect((await store.get("old"))?.username).toBe("o");
    expect((await store.get("new"))?.password).toBe("q");
    await expect(
      fileCredentials(file, aesGcmCipher(Buffer.alloc(32, 8))).get("new"),
    ).rejects.toThrow();
  });

  it("read as plain text, it names the setting instead of a parse error", async () => {
    const { aesGcmCipher } = await import("./cipher.js");
    const dir = mkdtempSync(join(tmpdir(), "credkeep-sealed-"));
    const file = join(dir, "c.json");
    await fileCredentials(file, aesGcmCipher(Buffer.alloc(32, 7))).put("s", {
      username: "u",
      password: "p",
    });
    await expect(fileCredentials(file).get("s")).rejects.toThrow(/opened with no cipher key/);
  });
});

describe("credentials under an app's own prefix", () => {
  it("names env entries with the prefix and reads only its own back", async () => {
    const o = { prefix: "MYAPP_CRED_" };
    const entries = credentialEnv(
      "s",
      { username: "u", password: "p", recoveryCodes: [], passkeys: [] },
      o,
    );
    expect(entries.map((e) => e.name)).toEqual(["MYAPP_CRED_S_USERNAME", "MYAPP_CRED_S_PASSWORD"]);
    const env = {
      ...Object.fromEntries(entries.map((e) => [e.name, e.value])),
      CRED_OTHER_USERNAME: "x",
      CRED_OTHER_PASSWORD: "y",
    };
    expect(await envCredentials(env, o).list()).toEqual(["s"]);
    expect(await envCredentials(env).list()).toEqual(["other"]);
  });
});

describe("a file sealed before the rename", () => {
  it("opens under the old magic and reseals under the new one", async () => {
    const { aesGcmCipher, isSealed } = await import("./cipher.js");
    const { readFileSync, writeFileSync } = await import("node:fs");
    const file = join(mkdtempSync(join(tmpdir(), "credkeep-legacy-")), "c.json");
    const cipher = aesGcmCipher(Buffer.alloc(32, 3));
    const plain = JSON.stringify({ sites: { a: { username: "a", password: "p" } } });
    const legacy = cipher.seal(plain).replace("credkeep-sealed-v1", "autobrowse-sealed-v1");
    writeFileSync(file, legacy);
    expect(isSealed(legacy)).toBe(true);
    const store = fileCredentials(file, cipher);
    expect((await store.get("a"))?.password).toBe("p");
    await store.put("b", { username: "b", password: "q" });
    expect(readFileSync(file, "utf8")).toContain("credkeep-sealed-v1");
  });
});

import { describe, expect, it } from "vitest";
import { memoryCredentials, pushCredentials, syncedCredentials } from "./credentials.js";
import { memoryEnvStore } from "./env-store.js";
import { changedFields, memoryCredentialHistory } from "./history.js";

describe("credential history", () => {
  it("a wrong write is undone: the state before it is a version, even a removed field", async () => {
    const shared = memoryEnvStore();
    const history = memoryCredentialHistory();
    const local = memoryCredentials();
    const s = syncedCredentials(local, shared, { history });
    // A person's account that signs in through Google, pushed before history existed.
    await local.put("li", { username: "me@gmail.com", via: "google" });
    await pushCredentials(local, shared, ["li"]);
    // The mistake: another account's password lands on it, then its push.
    await s.put("li", { username: "me@gmail.com", via: "google", password: "wrong" });
    const v = await history.versions("li");
    expect(v.map((x) => x.changed)).toEqual([["username", "via"], ["password"]]);
    expect(JSON.stringify(v)).not.toContain("wrong");
    // Restored: the version before goes back, the password leaves the shared store too.
    const before = await history.get("li", 1);
    if (!before) throw new Error("version 1 not kept");
    await s.put("li", before);
    expect(shared.values.CRED_LI_PASSWORD).toBeUndefined();
    expect((await history.versions("li")).map((x) => x.version)).toEqual([1, 2, 3]);
    // The wrong one is still there to read, should it have been the right one.
    expect((await history.get("li", 2))?.password).toBe("wrong");
  });
  it("keeps nothing twice, and a push that cannot keep the old state writes nothing", async () => {
    const history = memoryCredentialHistory();
    const cred = { username: "u", password: "p", recoveryCodes: [], passkeys: [] };
    await history.keep("a", cred);
    await history.keep("a", { ...cred });
    expect(await history.versions("a")).toHaveLength(1);
    const shared = memoryEnvStore({ CRED_A_USERNAME: "u", CRED_A_PASSWORD: "p" });
    const broken = { ...history, keep: async () => Promise.reject(new Error("history down")) };
    const local = memoryCredentials({ a: { username: "u", password: "new" } });
    await expect(pushCredentials(local, shared, ["a"], { history: broken })).rejects.toThrow(
      /history down/,
    );
    expect(shared.values.CRED_A_PASSWORD).toBe("p");
  });
  it("names what changed, never how", () => {
    const a = { username: "u", password: "p", recoveryCodes: ["1"], passkeys: [] };
    expect(changedFields(a, { ...a, recoveryCodes: [] })).toEqual(["recoveryCodes"]);
    expect(changedFields(null, a)).toEqual(["username", "password", "recoveryCodes"]);
  });
});

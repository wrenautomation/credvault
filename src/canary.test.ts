import { describe, expect, it } from "vitest";
import { memoryAudit } from "./audit.js";
import { CanaryTripped, canaryCredential, canaryStore } from "./canary.js";
import { memoryCredentials } from "./credentials.js";

describe("canary", () => {
  it("reading it is the alarm: recorded, told, refused; the value never lands in the ledger", async () => {
    const audit = memoryAudit();
    const told: string[] = [];
    const inner = memoryCredentials({ google: { username: "g", password: "real" } });
    const canary = canaryCredential("billing@example.com");
    await inner.put("stripe", canary);
    const store = canaryStore(inner, {
      audit,
      by: "login",
      notify: async (title) => {
        told.push(title);
      },
    });
    expect((await store.get("google"))?.username).toBe("g");
    expect((await store.list()).sort()).toEqual(["google", "stripe"]);
    await expect(store.get("stripe")).rejects.toBeInstanceOf(CanaryTripped);
    expect(told).toEqual(["canary tripped: stripe"]);
    expect(audit.uses.map((u) => `${u.credential} ${u.by} ${u.allowed}`)).toEqual([
      "stripe login (canary) false",
    ]);
    expect(JSON.stringify(audit.uses)).not.toContain(canary.password as string);
  });
});

import { describe, expect, it } from "vitest";
import { checkOwner, ownerCredentials, ownerPath } from "./owner.js";

type Sent = { input: Record<string, unknown> };

function fakeSts(expiresInMs: number, clock: { t: number }) {
  const sent: Sent[] = [];
  let n = 0;
  let fail = false;
  return {
    sent,
    failNext: () => {
      fail = true;
    },
    sts: {
      send: async (cmd: Sent) => {
        sent.push(cmd);
        await new Promise((r) => setTimeout(r, 5));
        if (fail) {
          fail = false;
          throw new Error("AccessDenied");
        }
        n++;
        return {
          Credentials: {
            AccessKeyId: `AKIA${n}`,
            SecretAccessKey: `secret${n}`,
            SessionToken: `token${n}`,
            Expiration: new Date(clock.t + expiresInMs),
          },
        };
      },
    },
  };
}

describe("owners", () => {
  it("names are lowercase, start with a letter, carry no path or tag tricks", () => {
    for (const ok of ["acme", "a", "client_7", "x".repeat(40)]) expect(checkOwner(ok)).toBe(ok);
    for (const bad of [
      "",
      "Acme",
      "7up",
      "a/b",
      "a-b",
      "a b",
      "../x",
      "*",
      "x".repeat(41),
      "acme\n",
    ])
      expect(() => checkOwner(bad)).toThrow(/owner/);
  });

  it("an owner's path sits under the app's root", () => {
    expect(ownerPath("/myapp", "acme")).toBe("/myapp/owners/acme");
    expect(ownerPath("/myapp/", "acme")).toBe("/myapp/owners/acme");
    expect(() => ownerPath("/myapp", "../wren")).toThrow();
  });

  it("assumes the role with the owner tag and reuses the session until 5 minutes before it ends", async () => {
    const clock = { t: 1_000_000 };
    const f = fakeSts(60 * 60_000, clock);
    const creds = ownerCredentials({
      roleArn: "arn:aws:iam::000000000000:role/owners",
      owner: "acme",
      region: "us-east-1",
      sts: f.sts as never,
      now: () => clock.t,
    });
    const a = await creds();
    expect(a).toMatchObject({
      accessKeyId: "AKIA1",
      secretAccessKey: "secret1",
      sessionToken: "token1",
    });
    expect(f.sent[0]?.input).toMatchObject({
      RoleArn: "arn:aws:iam::000000000000:role/owners",
      RoleSessionName: "owner-acme",
      DurationSeconds: 3600,
      Tags: [{ Key: "owner", Value: "acme" }],
    });
    clock.t += 54 * 60_000;
    expect((await creds()).accessKeyId).toBe("AKIA1");
    clock.t += 2 * 60_000;
    expect((await creds()).accessKeyId).toBe("AKIA2");
    expect(f.sent).toHaveLength(2);
  });

  it("callers at the same moment share one request", async () => {
    const clock = { t: 0 };
    const f = fakeSts(60 * 60_000, clock);
    const creds = ownerCredentials({
      roleArn: "r",
      owner: "acme",
      region: "us-east-1",
      sts: f.sts as never,
      now: () => clock.t,
    });
    const all = await Promise.all([creds(), creds(), creds()]);
    expect(new Set(all.map((c) => c.accessKeyId))).toEqual(new Set(["AKIA1"]));
    expect(f.sent).toHaveLength(1);
  });

  it("a refused request is not cached: the next call asks again", async () => {
    const clock = { t: 0 };
    const f = fakeSts(60 * 60_000, clock);
    const creds = ownerCredentials({
      roleArn: "r",
      owner: "acme",
      region: "us-east-1",
      sts: f.sts as never,
      now: () => clock.t,
    });
    f.failNext();
    await expect(creds()).rejects.toThrow("AccessDenied");
    expect((await creds()).accessKeyId).toBe("AKIA1");
  });

  it("a bad owner fails before any request", () => {
    const f = fakeSts(1, { t: 0 });
    expect(() =>
      ownerCredentials({ roleArn: "r", owner: "ACME", region: "us-east-1", sts: f.sts as never }),
    ).toThrow(/owner/);
    expect(f.sent).toHaveLength(0);
  });
});

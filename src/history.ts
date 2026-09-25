/**
 * Every state a credential has had, so a wrong write is undone. One SSM
 * SecureString per site under `<path>/<SITE>`; each change is a new version
 * of it (SSM keeps the last 100), and nothing here ever deletes one. The
 * shared store's own entries can be removed (a dropped password); this is
 * what remembers them.
 */

import { isDeepStrictEqual } from "node:util";
import {
  GetParameterCommand,
  GetParameterHistoryCommand,
  ParameterNotFound,
  PutParameterCommand,
  type SSMClient,
} from "@aws-sdk/client-ssm";
import { type Credential, credentialSchema, envSiteName } from "./credentials.js";

export interface CredentialVersion {
  version: number;
  /** When it was kept. */
  at: string | null;
  username: string;
  /** Fields that differ from the version before (all set ones for the first); names only. */
  changed: string[];
}

export interface CredentialHistory {
  /** Keep `cred` as the site's newest version, unless it already is. */
  keep(site: string, cred: Credential): Promise<void>;
  /** The newest kept version, or null when none is. */
  latest(site: string): Promise<Credential | null>;
  /** Oldest first. */
  versions(site: string): Promise<CredentialVersion[]>;
  get(site: string, version: number): Promise<Credential | null>;
}

const FIELDS = Object.keys(credentialSchema.shape) as (keyof Credential)[];
const isSet = (v: unknown) => v !== undefined && !(Array.isArray(v) && v.length === 0);

/** The field names that differ between two states of a credential. */
export function changedFields(before: Credential | null, after: Credential): string[] {
  return FIELDS.filter((f) => (before ? !isDeepStrictEqual(before[f], after[f]) : isSet(after[f])));
}

const summarize = (rows: { version: number; at: string | null; cred: Credential }[]) =>
  rows.map((r, i) => ({
    version: r.version,
    at: r.at,
    username: r.cred.username,
    changed: changedFields(rows[i - 1]?.cred ?? null, r.cred),
  }));

/** `google@ops` → `GOOGLE__OPS`: the parameter name, same rule as the env names. */
const paramName = envSiteName;

export function ssmCredentialHistory(ssm: SSMClient, path: string): CredentialHistory {
  const name = (site: string) => `${path}/${paramName(site)}`;
  const parse = (v: string | undefined) => (v ? credentialSchema.parse(JSON.parse(v)) : null);
  const read = async (id: string) => {
    try {
      const r = await ssm.send(new GetParameterCommand({ Name: id, WithDecryption: true }));
      return parse(r.Parameter?.Value);
    } catch (err) {
      if (err instanceof ParameterNotFound) return null;
      throw err;
    }
  };
  const self: CredentialHistory = {
    latest: (site) => read(name(site)),
    async keep(site, cred) {
      if (isDeepStrictEqual(await self.latest(site), cred)) return;
      await ssm.send(
        new PutParameterCommand({
          Name: name(site),
          Value: JSON.stringify(cred),
          Type: "SecureString",
          // Passkeys and recovery codes can pass 4 KB; SSM picks the advanced tier only then.
          Tier: "Intelligent-Tiering",
          Overwrite: true,
        }),
      );
    },
    async versions(site) {
      const rows: { version: number; at: string | null; cred: Credential }[] = [];
      let next: string | undefined;
      try {
        do {
          const r = await ssm.send(
            new GetParameterHistoryCommand({
              Name: name(site),
              WithDecryption: true,
              NextToken: next,
            }),
          );
          for (const p of r.Parameters ?? []) {
            const cred = parse(p.Value);
            if (cred && p.Version)
              rows.push({
                version: p.Version,
                at: p.LastModifiedDate?.toISOString() ?? null,
                cred,
              });
          }
          next = r.NextToken;
        } while (next);
      } catch (err) {
        if (err instanceof ParameterNotFound) return [];
        throw err;
      }
      return summarize(rows.sort((a, b) => a.version - b.version));
    },
    get: (site, version) => read(`${name(site)}:${version}`),
  };
  return self;
}

export function memoryCredentialHistory(now: () => Date = () => new Date()): CredentialHistory {
  const kept = new Map<string, { version: number; at: string; cred: Credential }[]>();
  return {
    async latest(site) {
      return kept.get(site)?.at(-1)?.cred ?? null;
    },
    async keep(site, cred) {
      const rows = kept.get(site) ?? [];
      if (isDeepStrictEqual(rows.at(-1)?.cred, cred)) return;
      rows.push({ version: rows.length + 1, at: now().toISOString(), cred: structuredClone(cred) });
      kept.set(site, rows);
    },
    async versions(site) {
      return summarize(kept.get(site) ?? []);
    },
    async get(site, version) {
      return kept.get(site)?.find((r) => r.version === version)?.cred ?? null;
    },
  };
}

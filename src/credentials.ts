/**
 * What it takes to sign in to a site, by site name (`github`, or
 * `google@ops` for a second account). Stored outside any repo or journal:
 * a sealed 0600 JSON file on a laptop, env entries in a container. Read at
 * the moment a login needs it, never carried on a plan or in a memo.
 */
import { existsSync, mkdirSync, readFileSync, renameSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname } from "node:path";
import { z } from "zod";
import { type Cipher, isSealed, plainCipher } from "./cipher.js";

const expandHome = (p: string) => (p.startsWith("~/") ? `${homedir()}${p.slice(1)}` : p);

export const credentialSchema = z
  .object({
    username: z.string().min(1),
    /** Absent when the account has none: it signs in through a provider (`via`). */
    password: z.string().min(1).optional(),
    /** The password before the last rotation: tried once when the site rejects the current one. */
    previousPassword: z.string().min(1).optional(),
    /** Base32 TOTP seed (the site's "manual entry key", spaces and dashes allowed); never a 6-digit code. */
    totpSecret: z
      .string()
      .transform((s) => s.replace(/[\s=-]/g, "").toUpperCase())
      .pipe(
        z
          .string()
          .regex(
            /^[A-Z2-7]{16,}$/,
            "totpSecret must be the base32 seed (16+ letters/digits), not a 6-digit code",
          ),
      )
      .optional(),
    /** One-time recovery codes the site handed out; used, then dropped. */
    recoveryCodes: z.array(z.string().min(1)).default([]),
    /** Where the site sends email codes; defaults to `username` when that is an address. */
    codesInbox: z.string().email().optional(),
    /** Passkeys enrolled by us (the virtual authenticator's export); loaded into the site's browser session. */
    passkeys: z
      .array(
        z.object({
          rpId: z.string(),
          credentialId: z.string(),
          privateKey: z.string(),
          userHandle: z.string().optional(),
          signCount: z.number(),
          isResidentCredential: z.boolean(),
        }),
      )
      .default([]),
    /** Sign in through this identity provider's button (`google`) instead of a password; the provider's own credential does the work. */
    via: z.string().min(1).optional(),
    /**
     * A tripwire, not an account: nothing legitimate ever reads it. A `get`
     * of a canary is an alarm (see canary.ts), and its password belongs on
     * no host.
     */
    canary: z.boolean().optional(),
    /** Where the sign-in page is, when the caller knows no login page of its own for the site. */
    url: z.string().url().optional(),
    /** When the account was made; a minted credential without it is a signup still owed. */
    madeAt: z.string().datetime().optional(),
  })
  .refine((c) => c.password || c.via, { message: "a credential has a password or a via provider" });

export type Credential = z.infer<typeof credentialSchema>;
export type CredentialInput = z.input<typeof credentialSchema>;

export interface CredentialStore {
  get(site: string): Promise<Credential | null>;
  put(site: string, cred: CredentialInput): Promise<void>;
  /** Site names only; never values. */
  list(): Promise<string[]>;
}

const fileSchema = z.object({ sites: z.record(z.string(), credentialSchema) });

/**
 * `{ "sites": { "<site>": Credential } }` at `path`, mode 0600, written
 * atomically, sealed with `cipher` (a plain file written earlier is still
 * read, and sealed on the next write).
 */
export function fileCredentials(path: string, cipher: Cipher = plainCipher): CredentialStore {
  const file = expandHome(path);
  type Data = { sites: Record<string, Credential> };
  // Opened and parsed once per version of the file: a `list` + `get` per name is one read, and
  // a file another process rewrote (its mtime or size moved) is read again. A stat per call.
  let cached: { stamp: string; data: Data } | null = null;
  const read = (): Data => {
    if (!existsSync(file)) {
      cached = null;
      return { sites: {} };
    }
    const st = statSync(file);
    const stamp = `${st.mtimeMs}:${st.size}`;
    if (cached?.stamp === stamp) return cached.data;
    const raw = readFileSync(file, "utf8");
    const data = fileSchema.parse(JSON.parse(isSealed(raw) ? cipher.open(raw) : raw));
    cached = { stamp, data };
    return data;
  };
  return {
    async get(site) {
      return read().sites[site] ?? null;
    },
    async put(site, cred) {
      const data = { sites: { ...read().sites, [site]: credentialSchema.parse(cred) } };
      mkdirSync(dirname(file), { recursive: true, mode: 0o700 });
      const tmp = `${file}.tmp`;
      writeFileSync(tmp, cipher.seal(JSON.stringify(data, null, 2)), { mode: 0o600 });
      renameSync(tmp, file);
      cached = null;
    },
    async list() {
      return Object.keys(read().sites);
    },
  };
}

export function memoryCredentials(init: Record<string, CredentialInput> = {}): CredentialStore {
  const sites = new Map(Object.entries(init).map(([k, v]) => [k, credentialSchema.parse(v)]));
  return {
    async get(site) {
      return sites.get(site) ?? null;
    },
    async put(site, cred) {
      sites.set(site, credentialSchema.parse(cred));
    },
    async list() {
      return [...sites.keys()];
    },
  };
}

/** How credentials travel as env: `<prefix><SITE>_<FIELD>`. Each app picks its own prefix. */
export interface EnvNaming {
  /** Default `CRED_`. */
  prefix?: string;
}

const DEFAULT_PREFIX = "CRED_";

/** `CRED_<SITE>_<FIELD>`: the env name a credential field travels under. */
export function credentialEnvName(site: string, field: string, o: EnvNaming = {}): string {
  return `${o.prefix ?? DEFAULT_PREFIX}${envSiteName(site)}_${field}`;
}

/** `google@ops` → `GOOGLE__OPS`, `google-admin` → `GOOGLE_ADMIN`: the account keeps its own mark so `list` can read it back. */
const envSiteName = (site: string): string =>
  site
    .replace(/@/g, "__")
    .replace(/[^a-zA-Z0-9_]+/g, "_")
    .toUpperCase();
const USERNAME = "_USERNAME";
const siteFromEnvName = (s: string): string =>
  s.toLowerCase().replace(/__/g, "@").replace(/_/g, "-");

/**
 * A credential as env entries, for the store the box reads: username,
 * password, TOTP seed, via provider, codes inbox. Recovery codes and
 * passkeys stay on the machine that holds the file.
 */
export function credentialEnv(
  site: string,
  cred: Credential,
  o: EnvNaming = {},
): { name: string; value: string }[] {
  const fields: [string, string | undefined][] = [
    ["USERNAME", cred.username],
    ["PASSWORD", cred.password],
    ["TOTP_SECRET", cred.totpSecret],
    ["VIA", cred.via],
    ["CODES_INBOX", cred.codesInbox],
  ];
  return fields
    .filter((f): f is [string, string] => Boolean(f[1]))
    .map(([field, value]) => ({ name: credentialEnvName(site, field, o), value }));
}

/**
 * `CRED_<SITE>_USERNAME` / `_PASSWORD` / `_TOTP_SECRET` / `_VIA` /
 * `_CODES_INBOX`: the container form, where a Secret becomes env. Read-only.
 */
export function envCredentials(
  env: NodeJS.ProcessEnv = process.env,
  o: EnvNaming = {},
): CredentialStore {
  const prefix = o.prefix ?? DEFAULT_PREFIX;
  const key = (site: string, field: string) => credentialEnvName(site, field, o);
  return {
    async get(site) {
      const username = env[key(site, "USERNAME")];
      const password = env[key(site, "PASSWORD")];
      const via = env[key(site, "VIA")];
      if (!username || !(password || via)) return null;
      const totpSecret = env[key(site, "TOTP_SECRET")];
      const codesInbox = env[key(site, "CODES_INBOX")];
      return credentialSchema.parse({
        username,
        ...(password ? { password } : {}),
        ...(totpSecret ? { totpSecret } : {}),
        ...(via ? { via } : {}),
        ...(codesInbox ? { codesInbox } : {}),
      });
    },
    async put(site) {
      throw new Error(`credentials for ${site}: env store is read-only; set ${key(site, "*")}`);
    },
    async list() {
      return Object.keys(env)
        .map((k) =>
          k.startsWith(prefix) && k.endsWith(USERNAME)
            ? k.slice(prefix.length, -USERNAME.length)
            : undefined,
        )
        .filter((s): s is string => Boolean(s))
        .map(siteFromEnvName);
    },
  };
}

/** The shared store's side of a sync (SSM, see env-store.ts). */
export interface CredentialEnvStore {
  all(): Promise<{ name: string; value: string }[]>;
  put(name: string, value: string): Promise<void>;
}

/**
 * This machine's credentials into the env store, every site or the named
 * ones: username, password, TOTP seed, via, codes inbox. Canaries never
 * travel (a tripwire belongs to one machine); passkeys and recovery codes
 * cannot. Answers what was pushed, never a value.
 */
export async function pushCredentials(
  local: CredentialStore,
  store: CredentialEnvStore,
  sites?: string[],
  o: EnvNaming = {},
): Promise<{ site: string; names: string[] }[]> {
  const chosen = sites?.length ? sites : await local.list();
  const out: { site: string; names: string[] }[] = [];
  for (const site of chosen) {
    const cred = await local.get(site);
    if (!cred) throw new Error(`no credential stored here for ${site}`);
    if (cred.canary) continue;
    const entries = credentialEnv(site, cred, o);
    for (const e of entries) await store.put(e.name, e.value);
    out.push({ site, names: entries.map((e) => e.name) });
  }
  return out;
}

/**
 * The env store's credentials into this machine's file, the other way: a
 * second laptop, or a box's file for a passkey site. A site already here is
 * kept unless `overwrite`, and even then its passkeys and recovery codes
 * stay (env never carries them). Answers what was written and what was kept.
 */
export async function pullCredentials(
  store: CredentialEnvStore,
  local: CredentialStore,
  sites?: string[],
  o: { overwrite?: boolean } & EnvNaming = {},
): Promise<{ written: string[]; kept: string[] }> {
  const env = Object.fromEntries((await store.all()).map((e) => [e.name, e.value]));
  const remote = envCredentials(env, o);
  const chosen = sites?.length ? sites : await remote.list();
  const written: string[] = [];
  const kept: string[] = [];
  for (const site of chosen) {
    const cred = await remote.get(site);
    if (!cred) throw new Error(`no credential in the shared store for ${site}: push it first`);
    const here = await local.get(site);
    if (here && !o.overwrite) {
      kept.push(site);
      continue;
    }
    await local.put(site, {
      ...cred,
      recoveryCodes: here?.recoveryCodes ?? cred.recoveryCodes,
      passkeys: here?.passkeys ?? cred.passkeys,
    });
    written.push(site);
  }
  return { written, kept };
}

/** First store that has the site wins; writes go to `write`, which defaults to the last store. */
export function layeredCredentials(
  stores: CredentialStore[],
  write: CredentialStore | undefined = stores.at(-1),
): CredentialStore {
  const first = write;
  if (!first) throw new Error("layeredCredentials needs at least one store");
  return {
    async get(site) {
      for (const s of stores) {
        const c = await s.get(site);
        if (c) return c;
      }
      return null;
    },
    put: (site, cred) => first.put(site, cred),
    async list() {
      const all = await Promise.all(stores.map((s) => s.list()));
      return [...new Set(all.flat())];
    },
  };
}

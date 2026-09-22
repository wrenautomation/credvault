/**
 * The one place a secret lives across machines: SSM Parameter Store, one
 * SecureString per name under the app's path (`/myapp/config/NAME`). KMS
 * at rest, IAM at the door, every read in CloudTrail. Values never enter
 * argv, logs or errors.
 */

import { existsSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import {
  DeleteParameterCommand,
  DescribeParametersCommand,
  GetParameterCommand,
  GetParametersByPathCommand,
  ParameterNotFound,
  PutParameterCommand,
  type SSMClient,
} from "@aws-sdk/client-ssm";

/** SSM throttles writes at a few a second; a push of thirty keys backs off and goes on rather than dying. */
async function patient<T>(
  call: () => Promise<T>,
  sleep = (ms: number) => new Promise((r) => setTimeout(r, ms)),
): Promise<T> {
  for (let attempt = 0; ; attempt++) {
    try {
      return await call();
    } catch (err) {
      const throttled =
        err instanceof Error &&
        (err.name === "ThrottlingException" || /Rate exceeded/i.test(err.message));
      if (!throttled || attempt >= 8) throw err;
      await sleep(200 * 2 ** attempt);
    }
  }
}

export const ENV_KEY = /^[A-Z][A-Z0-9_]*$/;

export interface EnvEntry {
  name: string;
  value: string;
}

/** What the store knows about an entry besides its value. */
export interface EnvListing {
  name: string;
  /** When the value last changed. */
  updatedAt: string | null;
  /** When the value stops working (a token's expiry), if whoever stored it knew. */
  expiresAt: string | null;
}

export interface PutOptions {
  /** ISO time the value stops working; absent = it does not, or nobody knows. */
  expiresAt?: string | undefined;
}

export interface EnvStore {
  /** Names, change and expiry times; never values. */
  list(): Promise<EnvListing[]>;
  get(name: string): Promise<string | null>;
  /** Every entry, decrypted: what a pull or a deploy reads. */
  all(): Promise<EnvEntry[]>;
  put(name: string, value: string, o?: PutOptions): Promise<void>;
  remove(name: string): Promise<boolean>;
}

/**
 * Entries that stop working within `withinMs` of `now` (already expired
 * included), soonest first: what a watcher re-mints.
 */
export function expiring(
  entries: readonly EnvListing[],
  withinMs: number,
  now = Date.now(),
): EnvListing[] {
  return entries
    .filter((e) => e.expiresAt !== null && Date.parse(e.expiresAt) - now <= withinMs)
    .sort((a, b) => (a.expiresAt ?? "").localeCompare(b.expiresAt ?? ""));
}

/** SSM keeps expiry in the parameter's description, which reads without decrypting. */
const EXPIRES = "expires ";
const describe = (o: PutOptions = {}) =>
  o.expiresAt ? `${EXPIRES}${new Date(o.expiresAt).toISOString()}` : "no expiry";
const expiryOf = (description: string | undefined): string | null =>
  description?.startsWith(EXPIRES) ? description.slice(EXPIRES.length) : null;

/** SSM under `prefix`: `/prefix/NAME`. The client comes in so tests pass a fake. */
export function ssmEnvStore(ssm: SSMClient, prefix: string): EnvStore {
  const path = (name: string) => {
    if (!ENV_KEY.test(name)) throw new Error(`env store: bad name ${name}`);
    return `${prefix}/${name}`;
  };
  const nameOf = (p: string | undefined) => p?.slice(prefix.length + 1) ?? "";
  const byName = <T extends { name: string }>(rows: T[]) =>
    rows.sort((a, b) => a.name.localeCompare(b.name));
  return {
    async list() {
      const out: EnvListing[] = [];
      let next: string | undefined;
      do {
        const r = await patient(() =>
          ssm.send(
            new DescribeParametersCommand({
              ParameterFilters: [{ Key: "Path", Option: "OneLevel", Values: [prefix] }],
              NextToken: next,
            }),
          ),
        );
        for (const p of r.Parameters ?? [])
          out.push({
            name: nameOf(p.Name),
            updatedAt: p.LastModifiedDate?.toISOString() ?? null,
            expiresAt: expiryOf(p.Description),
          });
        next = r.NextToken;
      } while (next);
      return byName(out);
    },
    async all() {
      const out: EnvEntry[] = [];
      let next: string | undefined;
      do {
        const r = await patient(() =>
          ssm.send(
            new GetParametersByPathCommand({
              Path: prefix,
              Recursive: false,
              WithDecryption: true,
              NextToken: next,
            }),
          ),
        );
        for (const p of r.Parameters ?? [])
          out.push({ name: nameOf(p.Name), value: p.Value ?? "" });
        next = r.NextToken;
      } while (next);
      return byName(out);
    },
    async get(name) {
      try {
        const r = await ssm.send(
          new GetParameterCommand({ Name: path(name), WithDecryption: true }),
        );
        return r.Parameter?.Value ?? null;
      } catch (err) {
        if (err instanceof ParameterNotFound) return null;
        throw err;
      }
    },
    async put(name, value, o) {
      if (!value) throw new Error(`env store: ${name} is empty`);
      await patient(() =>
        ssm.send(
          new PutParameterCommand({
            Name: path(name),
            Value: value,
            // Always said, so a re-mint without an expiry clears the old one.
            Description: describe(o),
            Type: "SecureString",
            // Past 4 KB (a service-account JSON) SSM needs the advanced tier; this picks it only then.
            Tier: "Intelligent-Tiering",
            Overwrite: true,
          }),
        ),
      );
    },
    async remove(name) {
      try {
        await ssm.send(new DeleteParameterCommand({ Name: path(name) }));
        return true;
      } catch (err) {
        if (err instanceof ParameterNotFound) return false;
        throw err;
      }
    },
  };
}

export function memoryEnvStore(initial: Record<string, string> = {}): EnvStore & {
  values: Record<string, string>;
} {
  const values = { ...initial };
  const expires = new Map<string, string>();
  return {
    values,
    list: async () =>
      Object.keys(values)
        .sort()
        .map((name) => ({ name, updatedAt: null, expiresAt: expiryOf(expires.get(name)) })),
    all: async () =>
      Object.entries(values)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([name, value]) => ({ name, value })),
    get: async (name) => values[name] ?? null,
    async put(name, value, o) {
      if (!ENV_KEY.test(name)) throw new Error(`env store: bad name ${name}`);
      values[name] = value;
      expires.set(name, describe(o));
    },
    async remove(name) {
      const had = name in values;
      delete values[name];
      expires.delete(name);
      return had;
    },
  };
}

/** The comment above a line that says when its value stops working: `# NAME expires <ISO>`. */
const EXPIRY_LINE = /^# ([A-Z][A-Z0-9_]*) expires (\S+)$/;

/**
 * A local `.env` as a store: 0600, one line per name, other lines untouched.
 * Expiry is a comment directly above the line, so a person reading the file
 * sees it too. A put also sets `env[name]`, so this process sees the value.
 */
export function envFileStore(path: string, env: NodeJS.ProcessEnv = process.env): EnvStore {
  const file = path.startsWith("~/") ? `${homedir()}${path.slice(1)}` : path;
  const text = () => (existsSync(file) ? readFileSync(file, "utf8") : "");
  const lines = () => {
    const out = text().split("\n");
    if (out.at(-1) === "") out.pop();
    return out;
  };
  const write = (out: string[]) => {
    const tmp = `${file}.tmp`;
    writeFileSync(tmp, out.length ? `${out.join("\n")}\n` : "", { mode: 0o600 });
    renameSync(tmp, file);
  };
  /** The file without `name`'s line and expiry comment; where the line was, or -1. */
  const without = (name: string) => {
    const out: string[] = [];
    let at = -1;
    for (const l of lines()) {
      if (EXPIRY_LINE.exec(l)?.[1] === name) continue;
      if (l.startsWith(`${name}=`)) {
        at = out.length;
        continue;
      }
      out.push(l);
    }
    return { out, at };
  };
  return {
    async list() {
      const expires = new Map<string, string>();
      for (const l of lines()) {
        const m = EXPIRY_LINE.exec(l);
        if (m?.[1] && m[2]) expires.set(m[1], m[2]);
      }
      return parseDotenv(text()).map(({ name }) => ({
        name,
        updatedAt: null,
        expiresAt: expires.get(name) ?? null,
      }));
    },
    all: async () => parseDotenv(text()),
    get: async (name) => parseDotenv(text()).find((e) => e.name === name)?.value ?? null,
    async put(name, value, o) {
      if (!ENV_KEY.test(name)) throw new Error(`env file: bad name ${name}`);
      if (/[\r\n]/.test(value)) throw new Error(`env file: ${name} spans lines`);
      const { out, at } = without(name);
      const add = [...(o?.expiresAt ? [`# ${name} ${describe(o)}`] : []), `${name}=${value}`];
      out.splice(at < 0 ? out.length : at, 0, ...add);
      write(out);
      env[name] = value;
    },
    async remove(name) {
      const { out, at } = without(name);
      if (at < 0) return false;
      write(out);
      delete env[name];
      return true;
    },
  };
}

/**
 * `KEY=VALUE` lines → entries. Comments, blanks and quotes as a shell would
 * read them; a value naming a readable file whose content is JSON (a
 * service account) is inlined so the store holds the secret, not a path.
 */
export function parseDotenv(text: string, readFile?: (path: string) => string | null): EnvEntry[] {
  const out: EnvEntry[] = [];
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#") || !line.includes("=")) continue;
    const i = line.indexOf("=");
    const name = line
      .slice(0, i)
      .trim()
      .replace(/^export\s+/, "");
    let value = line.slice(i + 1).trim();
    const q = value[0];
    if (q === '"' || q === "'") {
      const end = value.indexOf(q, 1);
      value = end > 0 ? value.slice(1, end) : value.slice(1);
    } else value = value.replace(/\s+#.*$/, "");
    if (!ENV_KEY.test(name) || !value) continue;
    if (readFile && !value.trimStart().startsWith("{") && /\.json$/.test(value)) {
      const inlined = readFile(value);
      if (inlined?.trimStart().startsWith("{")) value = inlined;
    }
    out.push({ name, value });
  }
  return out;
}

/** Entries → `KEY=VALUE` lines. A multi-line value cannot live in one line: `files` takes it and the line names the path. */
export function toDotenv(
  entries: EnvEntry[],
  files?: (name: string, value: string) => string,
): string {
  return `${entries
    .map(({ name, value }) => {
      if (!/[\r\n]/.test(value)) return `${name}=${value}`;
      if (!files) throw new Error(`${name} spans lines; give it a file`);
      return `${name}=${files(name, value)}`;
    })
    .join("\n")}\n`;
}

/** Entries → `export KEY='…'` lines for `eval "$(…)"`; single quotes are the one thing escaped. */
export function toExports(entries: EnvEntry[]): string {
  return `${entries
    .map(({ name, value }) => `export ${name}='${value.replace(/'/g, `'\\''`)}'`)
    .join("\n")}\n`;
}

/** Upsert `entries` into an env file's text; other lines untouched. */
export function upsertDotenv(text: string, entries: EnvEntry[]): string {
  const lines = text.split("\n");
  if (lines.at(-1) === "") lines.pop();
  for (const { name, value } of entries) {
    const line = `${name}=${value}`;
    const i = lines.findIndex((l) => l.startsWith(`${name}=`));
    if (i >= 0) lines[i] = line;
    else lines.push(line);
  }
  return `${lines.join("\n")}\n`;
}

/**
 * A file at rest. AES-256-GCM with a key that lives in the macOS Keychain
 * (made on first use, read through `security -i` so it is never on a
 * command line). Elsewhere (Linux, a container) secrets come from env and
 * the cipher is plain.
 */
import { spawnSync } from "node:child_process";
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

export interface Cipher {
  seal(plain: string): string;
  open(sealed: string): string;
}

/**
 * No sealing. `open` still refuses a sealed file: read as plain text it
 * would fail as a parse error three layers away, when the cause is always
 * that this machine seals and the caller passed no key.
 */
export const plainCipher: Cipher = {
  seal: (p) => p,
  open: (s) => {
    if (isSealed(s)) throw new Error("the file is sealed, but it was opened with no cipher key");
    return s;
  },
};

const MAGIC = "credvault-sealed-v1";
/** Files sealed before the vault left autobrowse: same format, older name. Read, and resealed on the next write. */
const MAGICS = [MAGIC, "credkeep-sealed-v1", "autobrowse-sealed-v1"];

/** Sealed text is one JSON line: {magic, iv, tag, data}, all base64. */
export function aesGcmCipher(key: Buffer): Cipher {
  if (key.length !== 32) throw new Error("cipher key must be 32 bytes");
  return {
    seal(plain) {
      const iv = randomBytes(12);
      const c = createCipheriv("aes-256-gcm", key, iv);
      const data = Buffer.concat([c.update(plain, "utf8"), c.final()]);
      return JSON.stringify({
        magic: MAGIC,
        iv: iv.toString("base64"),
        tag: c.getAuthTag().toString("base64"),
        data: data.toString("base64"),
      });
    },
    open(sealed) {
      const parsed = JSON.parse(sealed) as {
        magic?: string;
        iv?: string;
        tag?: string;
        data?: string;
      };
      if (!MAGICS.includes(parsed.magic ?? "") || !parsed.iv || !parsed.tag || !parsed.data)
        throw new Error("the file is not sealed by credvault");
      const d = createDecipheriv("aes-256-gcm", key, Buffer.from(parsed.iv, "base64"));
      d.setAuthTag(Buffer.from(parsed.tag, "base64"));
      return Buffer.concat([d.update(Buffer.from(parsed.data, "base64")), d.final()]).toString(
        "utf8",
      );
    },
  };
}

export function isSealed(text: string): boolean {
  const head = text.trimStart();
  return MAGICS.some((m) => head.startsWith(`{"magic":"${m}"`));
}

/** The Keychain item holding the key: one per app, so two tools never share a key by accident. */
export interface KeychainItem {
  service: string;
  account?: string;
}

/** Runs `security` in interactive mode so nothing secret is an argv. */
function security(commands: string): { status: number; out: string } {
  const r = spawnSync("security", ["-i"], { input: `${commands}\n`, encoding: "utf8" });
  return { status: r.status ?? 1, out: `${r.stdout}${r.stderr}` };
}

/** The item trusts the `security` tool itself, so reading it never raises the Keychain dialog. */
const TRUST = "-T /usr/bin/security";

const ACCOUNT = "credentials-key";
const ids = (item: KeychainItem) => `-s ${item.service} -a ${item.account ?? ACCOUNT}`;

function store(item: KeychainItem, hex: string): void {
  const added = security(`add-generic-password ${ids(item)} -w ${hex} -U ${TRUST}`);
  if (added.status !== 0)
    throw new Error(`keychain: could not store the key (${added.out.trim().slice(0, 120)})`);
}

/**
 * The 32-byte key from the login Keychain; created on first use with the
 * `security` tool trusted, so no dialog on later reads. Throws off macOS
 * or when the Keychain says no.
 */
export function keychainKey(item: KeychainItem): Buffer {
  if (process.platform !== "darwin") throw new Error("keychain cipher needs macOS");
  // One `security` subprocess per item per process: the key does not change while we run.
  const cached = keyCache.get(ids(item));
  if (cached) return cached;
  const found = security(`find-generic-password ${ids(item)} -w`);
  let hex = found.status === 0 ? found.out.match(/\b[0-9a-f]{64}\b/)?.[0] : undefined;
  if (!hex) {
    hex = randomBytes(32).toString("hex");
    store(item, hex);
  }
  const key = Buffer.from(hex, "hex");
  keyCache.set(ids(item), key);
  return key;
}
const keyCache = new Map<string, Buffer>();

/** Re-store the existing key with the tool trusted (an item made before `TRUST` prompts on every read). */
export function trustKeychainKey(item: KeychainItem): "retrusted" | "none" {
  const found = security(`find-generic-password ${ids(item)} -w`);
  const hex = found.out.match(/\b[0-9a-f]{64}\b/)?.[0];
  if (found.status !== 0 || !hex) return "none";
  security(`delete-generic-password ${ids(item)}`);
  store(item, hex);
  keyCache.delete(ids(item));
  return "retrusted";
}

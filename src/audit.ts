/**
 * Where secrets went. Every use, allowed or refused, is a line: which
 * credential, which field, which site, which page, by whom. Values are
 * never written here.
 */
import { chainedFile } from "./chain.js";

export interface SecretUse {
  at: string;
  /** The credential's store name (`google`, `google@will`); for an API key, its address (`exa@env-1`). */
  credential: string;
  field: "password" | "previousPassword" | "secret";
  /** The site the session is on; for an API key, the vendor. */
  site: string;
  /** The page, without its query (tokens ride in queries); for an API key, the endpoint. */
  url: string;
  /** Who used it: `login`, a flow name. */
  by: string;
  allowed: boolean;
  /** Whose credential it was: `wren` or an owner name. */
  owner?: string;
  /** For an API key: its `keyId`, so a line names the key without the value. */
  keyId?: string;
  /** Why it was used, in a few words. */
  reason?: string;
}

export interface SecretAudit {
  record(use: SecretUse): Promise<void>;
  /** Newest last. */
  recent(n?: number): Promise<SecretUse[]>;
}

/** JSON lines, owner-only, appended and hash-chained (chain.ts): `verifyChain` finds any edit. */
export function fileAudit(path: string): SecretAudit {
  const file = chainedFile<SecretUse>(path);
  return {
    async record(use) {
      await file.append(use);
    },
    recent: (n = 50) => file.recent(n),
  };
}

export function memoryAudit(): SecretAudit & { uses: SecretUse[] } {
  const uses: SecretUse[] = [];
  return {
    uses,
    async record(u) {
      uses.push(u);
    },
    async recent(n = 50) {
      return uses.slice(-n);
    },
  };
}

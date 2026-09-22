/**
 * Where secrets went. Every use, allowed or refused, is a line: which
 * credential, which field, which site, which page, by whom. Values are
 * never written here.
 */
import { chainedFile } from "./chain.js";

export interface SecretUse {
  at: string;
  /** The credential's store name (`google`, `google@will`). */
  credential: string;
  field: "password" | "previousPassword" | "secret";
  /** The site the session is on. */
  site: string;
  /** The page, without its query (tokens ride in queries). */
  url: string;
  /** Who used it: `login`, a flow name. */
  by: string;
  allowed: boolean;
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

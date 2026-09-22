/**
 * Canaries: credentials that exist only to be tripped. A real-looking
 * credential under a name a thief or a confused model would reach for
 * (`stripe`), with a random password nobody knows. Nothing legitimate asks
 * for it, so a `get` of it IS the incident: it is written to the audit
 * ledger, a person is told, and the read is refused.
 */
import type { SecretAudit } from "./audit.js";
import type { Credential, CredentialInput, CredentialStore } from "./credentials.js";
import { newPassword } from "./passwords.js";

export class CanaryTripped extends Error {
  constructor(readonly credential: string) {
    super(`credential ${credential} is a canary: nothing should read it`);
    this.name = "CanaryTripped";
  }
}

export interface CanaryOptions {
  audit?: SecretAudit | undefined;
  /** Tell a person; absent = the ledger line only. */
  notify?: ((title: string, body: string) => Promise<unknown>) | undefined;
  /** Who is reading, for the ledger (`login`, `explore`, a flow). */
  by?: string;
}

/** A credential that looks like an account and is not. Pick a username a thief would believe. */
export function canaryCredential(username: string): CredentialInput {
  return { username, password: newPassword(20), canary: true };
}

/**
 * The store with the wire armed: `get` of a canary records, notifies and
 * throws `CanaryTripped`; `list` and `put` pass through, so the operator
 * can still see and manage it by name.
 */
export function canaryStore(inner: CredentialStore, o: CanaryOptions = {}): CredentialStore {
  return {
    ...inner,
    async get(site): Promise<Credential | null> {
      const cred = await inner.get(site);
      if (!cred?.canary) return cred;
      await o.audit?.record({
        at: new Date().toISOString(),
        credential: site,
        field: "password",
        site,
        url: "",
        by: `${o.by ?? "get"} (canary)`,
        allowed: false,
      });
      await o
        .notify?.(
          `canary tripped: ${site}`,
          `something read the ${site} credential. Nothing legitimate does; check the audit ledger.`,
        )
        .catch(() => undefined);
      throw new CanaryTripped(site);
    },
  };
}

/** True when this credential must never be typed anywhere. */
export const isCanary = (cred: Pick<Credential, "canary"> | null | undefined): boolean =>
  cred?.canary === true;

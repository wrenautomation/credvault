# credvault

Keep the credentials an automation signs in with. Sealed at rest, shared through AWS SSM, every use audited, expiries watched.

No browser, no UI. The tool that signs in (a browser agent, a worker) reads from it. The tool that mints tokens writes to it.

```sh
npm install credvault
```

## What is in it

| Piece | What it does |
| --- | --- |
| `fileCredentials(path, cipher)` | Logins by site name (`github`, `google@ops`). A 0600 JSON file, sealed with AES-256-GCM. |
| `keychainKey({ service })` | The seal key, kept in the macOS Keychain. Made on first use. |
| `envCredentials(env, { prefix })` | The same logins read from env, for containers. Read-only. |
| `pushCredentials` / `pullCredentials` | Move logins between a laptop and the shared store: every field, passkeys and recovery codes as JSON. Canaries stay put. |
| `syncedCredentials` | The shared store is the truth, the local file the offline copy: a read checks the listing (no value read) and reads the values only when the site changed; pass `versions: versionsFile(path)` so other processes on the machine trust the copy too. A store with no change times is re-read every 60s. 3s timeout; writes land in both. No pull chore. |
| `ssmCredentialHistory(ssm, "/app/config/history")` | Every state a credential has had, one SSM parameter per site, a version per change (SSM keeps 100). Pass it as `history` to a push or `syncedCredentials`: a push keeps what the store held, then what it writes. It never deletes. `versions` names the fields that changed, never values. |
| `ssmEnvStore(ssm, "/app/config")` | Named values (API keys, tokens), one SSM SecureString each. Each value is decrypted once per version per process (every read is a KMS request, billed past 20k a month). |
| `envFileStore("~/.myapp/.env")` | The same, in a local 0600 `.env`. Expiry is a comment above the line. |
| `syncedEnvStore(local, shared)` | A machine's `.env` in front of the shared store: every put lands in both (local first, so a mint is never lost; a refused shared write still throws), reads prefer the local copy. A token minted on a laptop is on every machine. |
| `put(name, value, { expiresAt })` + `expiring(list, ms)` | Record when a token stops working. List what lapses soon, without decrypting anything. |
| `fileAudit(path)` | Where each secret went, one hash-chained line per use. `verifyChain` finds any edit. |
| `canaryStore(store)` | Reading a tripwire credential records it, tells a person, and throws. |
| `totp(seed)` | The current code from a TOTP seed. `findTotpSecret(pageText)` finds the seed on an enrollment page. |
| `newPassword()` | 24 characters, every class, no look-alikes. |

## Example

```ts
import { SSMClient } from "@aws-sdk/client-ssm";
import { aesGcmCipher, expiring, fileCredentials, keychainKey, ssmEnvStore, totp } from "credvault";

const logins = fileCredentials("~/.myapp/credentials.json", aesGcmCipher(keychainKey({ service: "myapp" })));
const github = await logins.get("github");
const code = github?.totpSecret ? totp(github.totpSecret) : null;

const keys = ssmEnvStore(new SSMClient({}), "/myapp/config");
await keys.put("NPM_TOKEN", token, { expiresAt: "2026-12-21T00:00:00Z" });
const soon = expiring(await keys.list(), 14 * 86_400_000);
```

## Rules it keeps

- Values never go into argv, logs or error messages. `list` returns names only.
- A sealed file opened without its key fails loudly. It never fails as a parse error.
- A wrong write is undone from history. A push that cannot keep the old state writes nothing.
- Each app has its own Keychain item, SSM path and env prefix, so two apps never share a secret by accident.

MIT

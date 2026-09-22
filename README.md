# credkeep

Keep the credentials an automation signs in with. Sealed at rest, shared through AWS SSM, every use audited, expiries watched.

No browser, no UI. The tool that signs in (a browser agent, a worker) reads from it. The tool that mints tokens writes to it.

```sh
npm install credkeep
```

## What is in it

| Piece | What it does |
| --- | --- |
| `fileCredentials(path, cipher)` | Logins by site name (`github`, `google@ops`). A 0600 JSON file, sealed with AES-256-GCM. |
| `keychainKey({ service })` | The seal key, kept in the macOS Keychain. Made on first use. |
| `envCredentials(env, { prefix })` | The same logins read from env, for containers. Read-only. |
| `pushCredentials` / `pullCredentials` | Move logins between a laptop and the shared store. Passkeys and recovery codes stay on the machine. |
| `ssmEnvStore(ssm, "/app/config")` | Named values (API keys, tokens), one SSM SecureString each. |
| `envFileStore("~/.myapp/.env")` | The same, in a local 0600 `.env`. Expiry is a comment above the line. |
| `put(name, value, { expiresAt })` + `expiring(list, ms)` | Record when a token stops working. List what lapses soon, without decrypting anything. |
| `fileAudit(path)` | Where each secret went, one hash-chained line per use. `verifyChain` finds any edit. |
| `canaryStore(store)` | Reading a tripwire credential records it, tells a person, and throws. |
| `totp(seed)` | The current code from a TOTP seed. `findTotpSecret(pageText)` finds the seed on an enrollment page. |
| `newPassword()` | 24 characters, every class, no look-alikes. |

## Example

```ts
import { SSMClient } from "@aws-sdk/client-ssm";
import { aesGcmCipher, expiring, fileCredentials, keychainKey, ssmEnvStore, totp } from "credkeep";

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
- Each app has its own Keychain item, SSM path and env prefix, so two apps never share a secret by accident.

MIT

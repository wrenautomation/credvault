/**
 * One named value, asked for by key at the moment it is needed (a card
 * number, an API key), never carried on a plan or in a log. Env is the
 * default source; the shared store (env-store.ts) is another.
 */
export interface SecretSource {
  get(key: string): Promise<string>;
}

/** A key in camelCase (`cardCvv`) → `SECRET_CARD_CVV` in the environment, under the app's prefix. */
export function envSecrets(env: NodeJS.ProcessEnv = process.env, prefix = "SECRET_"): SecretSource {
  return {
    async get(key) {
      const name = `${prefix}${key
        .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
        .replace(/[^a-zA-Z0-9]+/g, "_")
        .toUpperCase()}`;
      const value = env[name];
      if (!value) throw new Error(`secret ${key}: set ${name}`);
      return value;
    },
  };
}

export function memorySecrets(values: Record<string, string>): SecretSource {
  return {
    async get(key) {
      const v = values[key];
      if (v === undefined) throw new Error(`secret ${key}: not set`);
      return v;
    },
  };
}

/** A secret source that remembers what it handed out, so a caller can tell a secret's value from any other. */
export interface TrackingSecrets extends SecretSource {
  /** The key a value was handed out under, or null. */
  keyOf(value: string): string | null;
}

export function trackingSecrets(source: SecretSource): TrackingSecrets {
  const keys = new Map<string, string>();
  return {
    async get(key) {
      const value = await source.get(key);
      keys.set(value, key);
      return value;
    },
    keyOf: (value) => keys.get(value) ?? null,
  };
}

/**
 * Owners: one app, several tenants. Each owner has its own SSM path
 * (`/myapp/owners/<owner>/…`) and an AWS session that reaches only that
 * path: one shared role, scoped by the session tag `owner`
 * (`${aws:PrincipalTag/owner}` in its policy). A session without the tag
 * reaches nothing. The role's shape is in the README.
 */

import { SSMClient } from "@aws-sdk/client-ssm";
import { AssumeRoleCommand, STSClient } from "@aws-sdk/client-sts";

/** An owner's name: lowercase letters, digits and `_`, starting with a letter. Safe in a path, a tag and a session name. */
export const OWNER_NAME = /^[a-z][a-z0-9_]{0,39}$/;

export function checkOwner(owner: string): string {
  if (!OWNER_NAME.test(owner))
    throw new Error(
      `owner "${owner}": lowercase letters, digits and _, starting with a letter, 40 at most`,
    );
  return owner;
}

/** An owner's path under an app's root: `ownerPath("/myapp", "acme")` = `/myapp/owners/acme`. */
export function ownerPath(root: string, owner: string): string {
  return `${root.replace(/\/+$/, "")}/owners/${checkOwner(owner)}`;
}

export interface AwsCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
  expiration?: Date;
}

export interface OwnerSession {
  /** The shared owners role. */
  roleArn: string;
  owner: string;
  region: string;
  /** How long a session lasts, in seconds (default 3600). */
  durationSeconds?: number;
  /** Default: an STS client on the process's own credentials. */
  sts?: Pick<STSClient, "send">;
  now?: () => number;
}

/** Renew this long before a session ends, so no call carries a dying token. */
const RENEW_MS = 5 * 60_000;

/**
 * The owner's credentials, for any AWS client (`credentials:`): one
 * AssumeRole with the tag `owner=<owner>`, reused until 5 minutes before it
 * ends. Callers at the same moment share one request.
 */
export function ownerCredentials(o: OwnerSession): () => Promise<AwsCredentials> {
  const owner = checkOwner(o.owner);
  const sts = o.sts ?? new STSClient({ region: o.region });
  const now = o.now ?? Date.now;
  let current: AwsCredentials | undefined;
  let pending: Promise<AwsCredentials> | undefined;
  const fresh = (c: AwsCredentials) =>
    c.expiration === undefined || c.expiration.getTime() - now() > RENEW_MS;
  return () => {
    if (current && fresh(current)) return Promise.resolve(current);
    pending ??= sts
      .send(
        new AssumeRoleCommand({
          RoleArn: o.roleArn,
          RoleSessionName: `owner-${owner}`,
          DurationSeconds: o.durationSeconds ?? 3600,
          Tags: [{ Key: "owner", Value: owner }],
        }),
      )
      .then((out) => {
        const c = out.Credentials;
        if (!c?.AccessKeyId || !c.SecretAccessKey)
          throw new Error(`owner ${owner}: STS answered without credentials`);
        current = {
          accessKeyId: c.AccessKeyId,
          secretAccessKey: c.SecretAccessKey,
          ...(c.SessionToken ? { sessionToken: c.SessionToken } : {}),
          ...(c.Expiration ? { expiration: c.Expiration } : {}),
        };
        return current;
      })
      .finally(() => {
        pending = undefined;
      });
    return pending;
  };
}

/** An SSM client that acts as the owner. */
export function ownerSsmClient(o: OwnerSession): SSMClient {
  return new SSMClient({ region: o.region, credentials: ownerCredentials(o) });
}

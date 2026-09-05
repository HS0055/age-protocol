import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { agentIdOf, generateKeyPair, toPublicJwk, withKid, type PrivateJwk, type PublicJwk } from '@ageprotocol/receipts';

export const IDENTITY_VERSION = '0.1';
export const IDENTITY_USAGE = 'usage: agectl identity <init [--force] | show [--json]>';

export interface IdentityFile {
  identity_version: typeof IDENTITY_VERSION;
  id: string;
  created_at: string;
  private_jwk: PrivateJwk;
}

export interface IdentityIo {
  stdout(line: string): void;
  stderr(line: string): void;
}

export function identityHome(env: Record<string, string | undefined>): string {
  const configured = env.AGECTL_HOME;
  if (typeof configured === 'string' && configured.trim().length > 0) return configured;
  return join(homedir(), '.agectl');
}

export function identityPath(home: string): string {
  return join(home, 'identity.json');
}

// The id is derived from the key, so an identity exists the moment the key
// does, with no registry involved.
export function createIdentity(home: string, options: { force?: boolean; now?: () => Date } = {}): IdentityFile {
  const path = identityPath(home);
  if (existsSync(path) && !options.force) {
    throw new Error(`identity already exists at ${path} (use --force to replace it)`);
  }
  const { privateJwk, publicJwk } = generateKeyPair();
  const file: IdentityFile = {
    identity_version: IDENTITY_VERSION,
    id: agentIdOf(publicJwk),
    created_at: (options.now ?? (() => new Date()))().toISOString(),
    private_jwk: privateJwk,
  };
  mkdirSync(home, { recursive: true, mode: 0o700 });
  writeFileSync(path, `${JSON.stringify(file, null, 2)}\n`, { mode: 0o600 });
  chmodSync(path, 0o600);
  return file;
}

function isPrivateJwk(value: unknown): value is PrivateJwk {
  if (typeof value !== 'object' || value === null) return false;
  const jwk = value as Record<string, unknown>;
  return jwk.kty === 'OKP' && jwk.crv === 'Ed25519' && typeof jwk.x === 'string' && typeof jwk.d === 'string';
}

export function readIdentity(home: string): IdentityFile {
  const path = identityPath(home);
  if (!existsSync(path)) throw new Error(`no identity at ${path} (run agectl identity init)`);
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(path, 'utf8')) as unknown;
  } catch {
    throw new Error(`identity file at ${path} is corrupt: not valid JSON`);
  }
  const file = parsed as Partial<IdentityFile>;
  if (file.identity_version !== IDENTITY_VERSION || typeof file.id !== 'string' || !isPrivateJwk(file.private_jwk)) {
    throw new Error(`identity file at ${path} is corrupt: unexpected shape`);
  }
  let derived: string;
  try {
    derived = agentIdOf(toPublicJwk(file.private_jwk));
  } catch {
    throw new Error(`identity file at ${path} is corrupt: unusable key`);
  }
  if (derived !== file.id) throw new Error(`identity file at ${path} is corrupt: id does not match the key`);
  return {
    identity_version: IDENTITY_VERSION,
    id: file.id,
    created_at: typeof file.created_at === 'string' ? file.created_at : '',
    private_jwk: file.private_jwk,
  };
}

export function publicJwkOf(file: IdentityFile): PublicJwk {
  return withKid(toPublicJwk(file.private_jwk));
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export async function runIdentity(args: string[], home: string, io: IdentityIo): Promise<number> {
  const [subcommand, ...rest] = args;
  if (subcommand === 'init') {
    if (rest.some((arg) => arg !== '--force')) {
      io.stderr(IDENTITY_USAGE);
      return 2;
    }
    try {
      const file = createIdentity(home, { force: rest.includes('--force') });
      io.stdout('Agent identity created');
      io.stdout(`  id    ${file.id}`);
      io.stdout(`  key   ${identityPath(home)}`);
      return 0;
    } catch (error) {
      io.stderr(messageOf(error));
      return 1;
    }
  }
  if (subcommand === 'show') {
    if (rest.some((arg) => arg !== '--json')) {
      io.stderr(IDENTITY_USAGE);
      return 2;
    }
    try {
      const file = readIdentity(home);
      const key = publicJwkOf(file);
      if (rest.includes('--json')) {
        io.stdout(JSON.stringify({ id: file.id, created_at: file.created_at, key: identityPath(home), public_jwk: key }, null, 2));
      } else {
        io.stdout(`id      ${file.id}`);
        io.stdout(`key     ${identityPath(home)}`);
        // Members in alphabetical order, the same order canonical JSON uses.
        io.stdout(`public  ${JSON.stringify({ crv: key.crv, kid: key.kid, kty: key.kty, x: key.x })}`);
      }
      return 0;
    } catch (error) {
      io.stderr(messageOf(error));
      return 1;
    }
  }
  io.stderr(IDENTITY_USAGE);
  return 2;
}

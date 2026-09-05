import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { agentIdOf, toPublicJwk, type PrivateJwk } from '@ageprotocol/receipts';
import { createIdentity, readIdentity, identityHome, identityPath, runIdentity } from '../src/identity.ts';

function home(): string {
  return mkdtempSync(join(tmpdir(), 'agectl-identity-'));
}

function harness() {
  const out: string[] = [];
  const err: string[] = [];
  return { io: { stdout: (l: string) => out.push(l), stderr: (l: string) => err.push(l) }, out, err };
}

test('identityHome honours AGECTL_HOME and defaults under the home directory', () => {
  assert.equal(identityHome({ AGECTL_HOME: '/x/y' }), '/x/y');
  assert.equal(identityHome({ AGECTL_HOME: '  ' }).endsWith('/.agectl'), true);
  assert.equal(identityHome({}).endsWith('/.agectl'), true);
});

test('createIdentity writes a 0600 file whose id is derived from the key', () => {
  const dir = home();
  const file = createIdentity(dir);
  assert.equal(file.identity_version, '0.1');
  assert.equal(file.id, agentIdOf(toPublicJwk(file.private_jwk)));
  assert.equal(statSync(identityPath(dir)).mode & 0o777, 0o600);
  const onDisk = JSON.parse(readFileSync(identityPath(dir), 'utf8')) as { id: string; private_jwk: PrivateJwk };
  assert.equal(onDisk.id, file.id);
  assert.equal(onDisk.private_jwk.d, file.private_jwk.d);
  assert.deepEqual(readIdentity(dir), file);
});

test('init refuses to overwrite unless forced', async () => {
  const dir = home();
  const first = harness();
  assert.equal(await runIdentity(['init'], dir, first.io), 0);
  const id = readIdentity(dir).id;
  assert.equal(first.out[0], 'Agent identity created');
  assert.equal(first.out[1], `  id    ${id}`);
  assert.equal(first.out[2], `  key   ${identityPath(dir)}`);
  const again = harness();
  assert.equal(await runIdentity(['init'], dir, again.io), 1);
  assert.match(again.err[0] ?? '', /already exists/);
  assert.equal(readIdentity(dir).id, id);
  const forced = harness();
  assert.equal(await runIdentity(['init', '--force'], dir, forced.io), 0);
  assert.notEqual(readIdentity(dir).id, id);
});

test('show prints the id, key path, and public key, and --json prints data', async () => {
  const dir = home();
  createIdentity(dir);
  const text = harness();
  assert.equal(await runIdentity(['show'], dir, text.io), 0);
  const id = readIdentity(dir).id;
  assert.equal(text.out[0], `id      ${id}`);
  assert.equal(text.out[1], `key     ${identityPath(dir)}`);
  assert.match(text.out[2] ?? '', /^public  \{"crv":"Ed25519","kid":"/);
  const json = harness();
  assert.equal(await runIdentity(['show', '--json'], dir, json.io), 0);
  const parsed = JSON.parse(json.out.join('\n')) as { id: string; public_jwk: { kty: string; kid: string } };
  assert.equal(parsed.id, id);
  assert.equal(parsed.public_jwk.kty, 'OKP');
  assert.equal(`age:agent:${parsed.public_jwk.kid}`, id);
  assert.equal(json.out.join('\n').includes('"d"'), false);
});

test('show without an identity, a corrupt file, and unknown arguments are errors', async () => {
  const dir = home();
  const none = harness();
  assert.equal(await runIdentity(['show'], dir, none.io), 1);
  assert.match(none.err[0] ?? '', /no identity/);
  createIdentity(dir);
  writeFileSync(identityPath(dir), '{"id":"age:agent:x","identity_version":"0.1","private_jwk":{"kty":"OKP","crv":"Ed25519","x":"AA","d":"AA"}}');
  const corrupt = harness();
  assert.equal(await runIdentity(['show'], dir, corrupt.io), 1);
  assert.match(corrupt.err[0] ?? '', /corrupt/);
  const unknown = harness();
  assert.equal(await runIdentity(['rotate'], dir, unknown.io), 2);
  assert.equal(await runIdentity([], dir, unknown.io), 2);
  assert.equal(await runIdentity(['init', '--verbose'], dir, unknown.io), 2);
});

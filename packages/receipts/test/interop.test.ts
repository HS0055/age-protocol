import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

// docs/protocol/verify.py is a second implementation of verification: another
// language, another crypto library, its own canonicalizer, written from the
// specification rather than from this code. A format is interoperable when a
// stranger's implementation agrees, not when its author says so, and these
// tests are where that claim is actually checked.

const ROOT = join(import.meta.dirname, '..', '..', '..');
const VERIFIER = join(ROOT, 'docs', 'protocol', 'verify.py');
const VECTOR = join(ROOT, 'docs', 'protocol', 'golden-v0.1.json');

function python(): string | undefined {
  for (const candidate of ['python3', 'python']) {
    const probe = spawnSync(candidate, ['-c', 'import cryptography'], { encoding: 'utf8' });
    if (probe.status === 0) return candidate;
  }
  return undefined;
}

const PYTHON = python();
const missing = { skip: 'python3 with the cryptography package is not available' };
const when = PYTHON === undefined ? missing : {};

function run(...args: string[]) {
  return spawnSync(PYTHON as string, [VERIFIER, VECTOR, ...args], { encoding: 'utf8' });
}

test('a second implementation verifies every receipt in the golden vector', when, () => {
  const result = run();
  assert.equal(result.status, 0, result.stdout + result.stderr);
  // One verdict for the run, and every one of the three receipts reported.
  assert.match(result.stdout, /VERIFIED/);
  assert.doesNotMatch(result.stdout, /FAIL/);
  assert.equal((result.stdout.match(/\[PASS\] Receipt integrity/g) ?? []).length, 3);
  assert.equal((result.stdout.match(/\[PASS\] Agent signature/g) ?? []).length, 3);
  assert.equal((result.stdout.match(/\[PASS\] Root inclusion/g) ?? []).length, 3);
});

test('a second implementation rejects the same tampering this one does', when, () => {
  const vector = JSON.parse(readFileSync(VECTOR, 'utf8')) as {
    receipts: { receipt: Record<string, unknown> }[];
  };
  const genuine = vector.receipts[0]?.receipt as Record<string, unknown>;

  const tampered = JSON.parse(JSON.stringify(genuine)) as Record<string, unknown>;
  (tampered.action as Record<string, unknown>).files_changed = 300;
  assert.equal(run(JSON.stringify(tampered)).status, 1);

  // Content edited and the id recomputed to match: only the agent signature
  // catches this, which is the difference between a receipt and a log.
  const resealed = JSON.parse(JSON.stringify(genuine)) as Record<string, unknown>;
  (resealed.task as Record<string, unknown>).description = 'Something else entirely';
  const recomputed = run(JSON.stringify(resealed));
  assert.equal(recomputed.status, 1);
  assert.match(recomputed.stdout, /Agent signature/);
});

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createIdentity } from '../src/identity.ts';
import { main } from '../src/index.ts';

// These run real git. A fake cannot model a replace ref, a shallow graft, or
// an environment variable redirecting the repository, and each of those made
// the receipt describe something other than the commit it named.
function haveGit(): boolean {
  try {
    execFileSync('git', ['--version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

const when = haveGit() ? {} : { skip: 'git is not available' };

function repo(): string {
  const dir = mkdtempSync(join(tmpdir(), 'agectl-git-'));
  const git = (...args: string[]) => execFileSync('git', ['-C', dir, ...args], { encoding: 'utf8' });
  git('init', '-q', '-b', 'main');
  git('config', 'user.email', 'a@example.com');
  git('config', 'user.name', 'A');
  git('config', 'commit.gpgsign', 'false');
  return dir;
}

function commit(dir: string, name: string, body: string, message: string): string {
  writeFileSync(join(dir, name), body);
  execFileSync('git', ['-C', dir, 'add', '.'], { encoding: 'utf8' });
  execFileSync('git', ['-C', dir, 'commit', '-q', '-m', message], { encoding: 'utf8' });
  return execFileSync('git', ['-C', dir, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
}

async function emitInto(dir: string, home: string, args: string[]): Promise<number> {
  const previous = process.env.AGECTL_HOME;
  process.env.AGECTL_HOME = home;
  try {
    return await main(['emit', '--task', 'a task', '--repo', dir, ...args], process.env);
  } finally {
    if (previous === undefined) delete process.env.AGECTL_HOME;
    else process.env.AGECTL_HOME = previous;
  }
}

test('a replace ref cannot make a receipt describe another commit', when, async () => {
  const dir = repo();
  const home = mkdtempSync(join(tmpdir(), 'agectl-home-'));
  createIdentity(home);
  try {
    const real = commit(dir, 'a.txt', 'real', 'the real commit');
    const other = commit(dir, 'b.txt', 'other', 'the replacement');
    // git filter-repo leaves these behind by default, so this is not only an
    // adversarial shape.
    execFileSync('git', ['-C', dir, 'replace', real, other], { encoding: 'utf8' });

    const out = join(dir, 'r.json');
    assert.equal(await emitInto(dir, home, ['--commit', real, '--out', out]), 0);
    const receipt = JSON.parse(readFileSync(out, 'utf8')) as { action: Record<string, unknown> };
    assert.equal(receipt.action.subject, 'the real commit',
      'the receipt must describe the object it names, not its replacement');
    assert.equal(receipt.action.commit, real);
  } finally {
    rmSync(dir, { recursive: true, force: true });
    rmSync(home, { recursive: true, force: true });
  }
});

test('GIT_DIR cannot redirect emit away from the repository it was given', when, async () => {
  const alpha = repo();
  const beta = repo();
  const home = mkdtempSync(join(tmpdir(), 'agectl-home-'));
  createIdentity(home);
  const previous = process.env.GIT_DIR;
  try {
    commit(alpha, 'a.txt', 'alpha', 'a commit in alpha');
    const wanted = commit(beta, 'b.txt', 'beta', 'a commit in beta');
    // This is the environment inside a post-commit hook.
    process.env.GIT_DIR = join(alpha, '.git');

    const out = join(beta, 'r.json');
    assert.equal(await emitInto(beta, home, ['--out', out]), 0);
    const receipt = JSON.parse(readFileSync(out, 'utf8')) as { action: Record<string, unknown> };
    assert.equal(receipt.action.commit, wanted);
    assert.equal(receipt.action.subject, 'a commit in beta');
  } finally {
    if (previous === undefined) delete process.env.GIT_DIR;
    else process.env.GIT_DIR = previous;
    rmSync(alpha, { recursive: true, force: true });
    rmSync(beta, { recursive: true, force: true });
    rmSync(home, { recursive: true, force: true });
  }
});

test('a shallow clone refuses rather than counting the whole repository as changed', when, async () => {
  const upstream = repo();
  const home = mkdtempSync(join(tmpdir(), 'agectl-home-'));
  createIdentity(home);
  let shallow = '';
  try {
    for (let i = 0; i < 12; i += 1) writeFileSync(join(upstream, `f${i}.txt`), `file ${i}\n`);
    execFileSync('git', ['-C', upstream, 'add', '.'], { encoding: 'utf8' });
    execFileSync('git', ['-C', upstream, 'commit', '-q', '-m', 'twelve files'], { encoding: 'utf8' });
    commit(upstream, 'f0.txt', 'changed\n', 'change one line in one file');

    shallow = mkdtempSync(join(tmpdir(), 'agectl-shallow-'));
    rmSync(shallow, { recursive: true, force: true });
    execFileSync('git', ['clone', '-q', '--depth', '1', `file://${upstream}`, shallow], { encoding: 'utf8' });
    assert.equal(
      execFileSync('git', ['-C', shallow, 'rev-parse', '--is-shallow-repository'], { encoding: 'utf8' }).trim(),
      'true');

    // Left alone, git diffs the grafted commit against the empty tree and
    // every file in the repository reads as changed.
    assert.equal(await emitInto(shallow, home, ['--out', join(shallow, 'r.json')]), 2);

    execFileSync('git', ['-C', shallow, 'fetch', '-q', '--unshallow'], { encoding: 'utf8' });
    const out = join(shallow, 'r.json');
    assert.equal(await emitInto(shallow, home, ['--out', out]), 0);
    const receipt = JSON.parse(readFileSync(out, 'utf8')) as { action: Record<string, unknown> };
    assert.equal(receipt.action.files_changed, 1);
    assert.equal(receipt.action.insertions, 1);
    assert.equal(receipt.action.deletions, 1);
  } finally {
    rmSync(upstream, { recursive: true, force: true });
    if (shallow !== '') rmSync(shallow, { recursive: true, force: true });
    rmSync(home, { recursive: true, force: true });
  }
});

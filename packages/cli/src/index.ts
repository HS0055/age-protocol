import { execFile } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { writeFile } from 'node:fs/promises';
import { runVerify, VERIFY_USAGE } from './verify.ts';
import { runIdentity, identityHome, IDENTITY_USAGE } from './identity.ts';
import { runEmit, EMIT_USAGE } from './emit.ts';

const USAGE = [
  'usage: agectl <command>',
  '',
  'commands:',
  '  verify     verify an AGE receipt',
  '  identity   create or show the agent identity on this machine',
  '  emit       write a receipt for a commit this machine just made',
  '',
  VERIFY_USAGE,
  IDENTITY_USAGE,
  EMIT_USAGE,
].join('\n');

function git(args: string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    // A large diff can exceed the default buffer, and a truncated numstat
    // would silently undercount rather than fail.
    // Force UTF-8 rather than inheriting i18n.logOutputEncoding from the
    // repository, which can otherwise deliver a subject in another encoding
    // that arrives as replacement characters and gets signed that way.
    // --no-replace-objects: a replace ref makes git report one commit's
    // content under another's hash, and git filter-repo leaves these behind
    // by default. The receipt must describe the object it names.
    const forced = ['--no-replace-objects', '-c', 'i18n.logOutputEncoding=UTF-8', '-c', 'core.quotePath=true', ...args];
    // GIT_DIR and friends silently override -C, which is exactly the
    // environment inside a post-commit hook: asking about one repository
    // would describe another. The flag the caller passed must win.
    const { GIT_DIR: _d, GIT_WORK_TREE: _w, GIT_INDEX_FILE: _i, GIT_COMMON_DIR: _c, ...clean } = process.env;
    execFile('git', forced, { maxBuffer: 64 * 1024 * 1024, encoding: 'utf8', env: clean }, (error, stdout, stderr) => {
      if (error) reject(new Error(`git ${args.join(' ')}: ${String(stderr || error.message).trim()}`));
      else resolve(stdout);
    });
  });
}

function gitCommitExists(repo: string, commit: string): Promise<boolean> {
  return new Promise((resolve) => {
    // Same scrubbing as git() above. This one decides a verification verdict,
    // so an environment variable that redirected it would make the verifier
    // state something false, which is the thing this product sells against.
    const { GIT_DIR: _d, GIT_WORK_TREE: _w, GIT_INDEX_FILE: _i, GIT_COMMON_DIR: _c, ...clean } = process.env;
    execFile('git', ['--no-replace-objects', '-C', repo, 'cat-file', '-t', commit], { env: clean }, (error, stdout) => {
      resolve(!error && stdout.trim() === 'commit');
    });
  });
}

async function fetchText(url: string): Promise<string> {
  const response = await fetch(url);
  if (!response.ok) throw new Error(`HTTP ${response.status} fetching ${url}`);
  return response.text();
}

export async function main(argv: string[], env: Record<string, string | undefined> = process.env): Promise<number> {
  const [command, ...rest] = argv;
  const io = {
    readFile: (path: string) => readFile(path, 'utf8'),
    fetchText,
    gitCommitExists,
    stdout: (line: string) => console.log(line),
    stderr: (line: string) => console.error(line),
  };
  switch (command) {
    case 'verify':
      return runVerify(rest, io);
    case 'identity':
      return runIdentity(rest, identityHome(env), io);
    case 'emit':
      return runEmit(rest, identityHome(env), {
        git,
        stdout: io.stdout,
        stderr: io.stderr,
        writeFile: (path: string, text: string) => writeFile(path, text, 'utf8'),
        now: () => new Date(),
      });
    case undefined:
    case '--help':
    case '-h':
      console.log(USAGE);
      return command === undefined ? 2 : 0;
    default:
      console.error(`unknown command: ${command}`);
      console.error(USAGE);
      return 2;
  }
}

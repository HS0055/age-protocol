import { execFile } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { runVerify, VERIFY_USAGE } from './verify.ts';
import { runIdentity, identityHome, IDENTITY_USAGE } from './identity.ts';

const USAGE = [
  'usage: agectl <command>',
  '',
  'commands:',
  '  verify     verify an AGE receipt',
  '  identity   create or show the agent identity on this machine',
  '',
  VERIFY_USAGE,
  IDENTITY_USAGE,
].join('\n');

function gitCommitExists(repo: string, commit: string): Promise<boolean> {
  return new Promise((resolve) => {
    execFile('git', ['-C', repo, 'cat-file', '-t', commit], (error, stdout) => {
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

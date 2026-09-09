import { createHash } from 'node:crypto';
import { agentSign, type Receipt, type ReceiptCore } from '@ageprotocol/receipts';
import { publicJwkOf, readIdentity, type IdentityFile } from './identity.ts';

export const EMIT_USAGE = 'usage: agectl emit --task <text> [--repo <path>] [--commit <ref>] [--prompt <text>] [--runtime <name>] [--out <file>]';

// Everything an emitted receipt says about a commit comes from git. Nothing
// here estimates, rounds, or fills in a plausible value: a receipt that
// guesses is a receipt that lies, and the whole point is that it does not.
export interface CommitFacts {
  commit: string;
  parent?: string;
  authored_at: string;
  subject: string;
  files_changed: number;
  insertions: number;
  deletions: number;
  object_digest: string;
}

export interface EmitIo {
  git(args: string[]): Promise<string>;
  stdout(line: string): void;
  stderr(line: string): void;
  writeFile(path: string, text: string): Promise<void>;
  now(): Date;
}

export interface EmitOptions {
  task: string;
  repo: string;
  commit: string;
  prompt?: string;
  runtime?: string;
  out?: string;
  json?: boolean;
}

function digestOf(text: string): string {
  return `sha256:${createHash('sha256').update(text, 'utf8').digest('hex')}`;
}

// A UTC instant with no fractional seconds. Two agents on the same commit
// should differ in what they did, not in how their clock prints.
export function timestampOf(date: Date): string {
  return `${date.toISOString().slice(0, 19)}Z`;
}

const COMMIT_HASH = /^[0-9a-f]{40}$/;
const NUMSTAT_LINE = /^(\d+|-)\t(\d+|-)\t/;

export function parseNumstat(text: string): { files_changed: number; insertions: number; deletions: number } {
  let files = 0;
  let insertions = 0;
  let deletions = 0;
  for (const line of text.split('\n')) {
    const match = NUMSTAT_LINE.exec(line);
    if (!match) continue;
    files += 1;
    // A binary file reports "-" for both counts. It still changed, so it
    // counts as a file; its lines are not lines and are not invented.
    if (match[1] !== '-') insertions += Number(match[1]);
    if (match[2] !== '-') deletions += Number(match[2]);
  }
  return { files_changed: files, insertions, deletions };
}

export async function commitFacts(io: EmitIo, repo: string, ref: string): Promise<CommitFacts> {
  const commit = (await io.git(['-C', repo, 'rev-parse', `${ref}^{commit}`])).trim();
  if (!COMMIT_HASH.test(commit)) throw new Error(`git did not resolve ${ref} to a commit`);

  const [authored, subject] = (await io.git(['-C', repo, 'show', '-s', '--format=%cI%n%s', commit])).split('\n');
  if (authored === undefined || subject === undefined) throw new Error(`git returned no metadata for ${commit}`);

  // The commit object itself, hashed. Anyone with the repository can
  // reproduce this digest, which is what makes it worth recording.
  const object = await io.git(['-C', repo, 'cat-file', 'commit', commit]);

  const parents = (await io.git(['-C', repo, 'rev-list', '--parents', '-n', '1', commit])).trim().split(/\s+/).slice(1);
  const numstat = await io.git(['-C', repo, 'show', '--numstat', '--format=', commit]);

  const facts: CommitFacts = {
    commit,
    authored_at: `${new Date(authored.trim()).toISOString().slice(0, 19)}Z`,
    subject: subject.trim(),
    ...parseNumstat(numstat),
    object_digest: digestOf(object),
  };
  const parent = parents[0];
  if (parent !== undefined && COMMIT_HASH.test(parent)) facts.parent = parent;
  return facts;
}

export async function originOf(io: EmitIo, repo: string): Promise<string | undefined> {
  try {
    const url = (await io.git(['-C', repo, 'remote', 'get-url', 'origin'])).trim();
    return url === '' ? undefined : url;
  } catch {
    // A repository with no origin is still a repository. The receipt says
    // less about it rather than saying something untrue.
    return undefined;
  }
}

export function buildCore(
  identity: IdentityFile,
  facts: CommitFacts,
  options: EmitOptions,
  origin: string | undefined,
  now: Date,
): ReceiptCore {
  const action: Record<string, unknown> = {
    type: 'git.commit',
    commit: facts.commit,
    subject: facts.subject,
    files_changed: facts.files_changed,
    insertions: facts.insertions,
    deletions: facts.deletions,
    authored_at: facts.authored_at,
  };
  if (origin !== undefined) action.repository = origin;
  if (facts.parent !== undefined) action.parent = facts.parent;

  const inputs = options.prompt === undefined
    ? []
    : [{ kind: 'prompt', digest: digestOf(options.prompt) }];

  const environment: Record<string, unknown> = { runtime: options.runtime ?? 'agectl/0.1.1' };
  if (origin !== undefined) environment.workspace = origin;

  return {
    receipt_version: '0.1',
    agent: identity.id,
    timestamp: timestampOf(now),
    task: { description: options.task },
    action: action as ReceiptCore['action'],
    inputs,
    outputs: [{ kind: 'commit', digest: facts.object_digest, ref: facts.commit }],
    environment,
    policy: null,
  };
}

export async function emit(identity: IdentityFile, options: EmitOptions, io: EmitIo): Promise<Receipt> {
  const facts = await commitFacts(io, options.repo, options.commit);
  const origin = await originOf(io, options.repo);
  const core = buildCore(identity, facts, options, origin, io.now());
  return agentSign(core, identity.private_jwk);
}

interface ParsedEmitArgs {
  options: EmitOptions;
  error?: string;
}

const FLAGS = new Set(['--task', '--repo', '--commit', '--prompt', '--runtime', '--out']);

export function parseEmitArgs(args: string[]): ParsedEmitArgs {
  const options: EmitOptions = { task: '', repo: '.', commit: 'HEAD' };
  const fail = (error: string): ParsedEmitArgs => ({ options, error });
  for (let i = 0; i < args.length; i += 1) {
    const flag = args[i] as string;
    if (flag === '--json') {
      options.json = true;
      continue;
    }
    if (!FLAGS.has(flag)) return fail(`unknown argument: ${flag}`);
    const value = args[i + 1];
    if (value === undefined || value.startsWith('--')) return fail(`${flag} needs a value`);
    i += 1;
    if (flag === '--task') options.task = value;
    else if (flag === '--repo') options.repo = value;
    else if (flag === '--commit') options.commit = value;
    else if (flag === '--prompt') options.prompt = value;
    else if (flag === '--runtime') options.runtime = value;
    else options.out = value;
  }
  if (options.task === '') return fail('--task is required: say what the work was');
  return { options };
}

export async function runEmit(args: string[], home: string, io: EmitIo): Promise<number> {
  const { options, error } = parseEmitArgs(args);
  if (error !== undefined) {
    io.stderr(error);
    io.stderr(EMIT_USAGE);
    return 2;
  }

  let identity: IdentityFile;
  try {
    identity = readIdentity(home);
  } catch (problem) {
    io.stderr(problem instanceof Error ? problem.message : String(problem));
    io.stderr('run agectl identity init first');
    return 2;
  }

  let receipt: Receipt;
  try {
    receipt = await emit(identity, options, io);
  } catch (problem) {
    io.stderr(problem instanceof Error ? problem.message : String(problem));
    return 2;
  }

  const text = `${JSON.stringify(receipt, null, 2)}\n`;
  if (options.out !== undefined) {
    await io.writeFile(options.out, text);
    if (!options.json) {
      io.stdout('Receipt emitted');
      io.stdout(`  id      ${receipt.id}`);
      io.stdout(`  agent   ${identity.id}`);
      io.stdout(`  commit  ${String((receipt.action as Record<string, unknown>).commit).slice(0, 7)}`);
      io.stdout(`  file    ${options.out}`);
      io.stdout('');
      io.stdout('It is unregistered, which is valid. Verify it with:');
      io.stdout(`  agectl verify ${options.out} --repo ${options.repo}`);
    }
    return 0;
  }
  io.stdout(text.trimEnd());
  return 0;
}

// Kept so the public key is part of this module's surface: an emitted receipt
// embeds it, and a caller may want it without reaching into identity.ts.
export { publicJwkOf };

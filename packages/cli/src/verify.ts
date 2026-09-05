import {
  isPublicJwk, keyMapFromJwks, verifyReceipt, verifyRoot, verifyRootInclusion, registrySignaturesOf,
  type Check, type CheckStatus, type PublicJwk, type Receipt, type RootDocument, type RootProof,
} from '@ageprotocol/receipts';

export interface VerifyIo {
  readFile(path: string): Promise<string>;
  fetchText(url: string): Promise<string>;
  gitCommitExists(repo: string, commit: string): Promise<boolean>;
  stdout(line: string): void;
  stderr(line: string): void;
}

export const VERIFY_USAGE =
  'usage: agectl verify <receipt.json> [--jwks <file or url>] [--repo <path>] [--root <root.json> --proof <proof.json>] [--offline] [--json]';

const VALUE_FLAGS = ['jwks', 'repo', 'root', 'proof'];
const BOOLEAN_FLAGS = ['offline', 'json'];

interface ParsedArgs {
  receipt: string;
  jwks?: string;
  repo?: string;
  root?: string;
  proof?: string;
  offline: boolean;
  json: boolean;
}

function parseArgs(args: string[]): ParsedArgs | string {
  const positional: string[] = [];
  const values: Record<string, string> = {};
  const booleans = new Set<string>();
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i] as string;
    if (!arg.startsWith('--')) {
      positional.push(arg);
      continue;
    }
    const name = arg.slice(2);
    if (BOOLEAN_FLAGS.includes(name)) {
      booleans.add(name);
      continue;
    }
    if (!VALUE_FLAGS.includes(name)) return `unknown flag: ${arg}`;
    const value = args[i + 1];
    if (value === undefined || value.startsWith('--')) return `missing value for ${arg}`;
    values[name] = value;
    i += 1;
  }
  if (positional.length !== 1) return 'expected exactly one receipt file';
  if ((values.root && !values.proof) || (values.proof && !values.root)) return '--root and --proof must be given together';
  return {
    receipt: positional[0] as string,
    jwks: values.jwks,
    repo: values.repo,
    root: values.root,
    proof: values.proof,
    offline: booleans.has('offline'),
    json: booleans.has('json'),
  };
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isUrl(value: string): boolean {
  return value.startsWith('http://') || value.startsWith('https://');
}

const HEX_32_BYTES = /^[0-9a-fA-F]{64}$/;
const COMMIT_HASH = /^[0-9a-f]{40}$/;

// Input shapes are checked before any check runs, so a malformed file is an
// input error with a message and never an exception out of a check.
function receiptProblem(value: unknown): string | undefined {
  if (!isObject(value)) return 'receipt must be an object';
  if (typeof value.receipt_version !== 'string') return 'receipt has no receipt_version';
  if (typeof value.id !== 'string') return 'receipt id must be a string';
  if (typeof value.agent !== 'string') return 'receipt agent must be a string';
  if (!isObject(value.action) || typeof value.action.type !== 'string') return 'receipt action.type must be a string';
  if (!Array.isArray(value.inputs) || !Array.isArray(value.outputs)) return 'receipt inputs and outputs must be arrays';
  // Deliberately no per-entry shape check here. verifyReceipt judges every
  // entry and reports the bad ones, and roles this version does not know are
  // meant to be carried without breaking anything. Rejecting the whole file
  // for an entry shaped differently would make the reference verifier the
  // first thing to break when a runtime or hardware signer appears.
  if (!Array.isArray(value.signatures)) return 'receipt signatures must be an array';
  return undefined;
}

function jwksProblem(value: unknown): string | undefined {
  if (!isObject(value) || !Array.isArray(value.keys)) return 'jwks has no keys array';
  for (let i = 0; i < value.keys.length; i += 1) {
    if (!isPublicJwk(value.keys[i])) return `jwks key ${i} is not a public JWK`;
  }
  return undefined;
}

function rootProblem(value: unknown): string | undefined {
  if (!isObject(value)) return 'root file must be an object';
  if (typeof value.root_version !== 'string') return 'root file has no root_version';
  if (typeof value.registry !== 'string') return 'root file registry must be a string';
  if (typeof value.date !== 'string') return 'root file date must be a string';
  if (!Number.isInteger(value.sequence_start) || !Number.isInteger(value.sequence_end)) return 'root file sequence range must be integers';
  if (typeof value.root !== 'string') return 'root file root must be a string';
  if (typeof value.signature !== 'string') return 'root file signature must be a string';
  return undefined;
}

function proofProblem(value: unknown): string | undefined {
  if (!isObject(value)) return 'proof file must be an object';
  if (!Number.isInteger(value.sequence)) return 'proof sequence must be an integer';
  if (!Number.isInteger(value.index)) return 'proof index must be an integer';
  if (!Number.isInteger(value.size)) return 'proof size must be an integer';
  if (!Array.isArray(value.path)) return 'proof path must be an array';
  for (let i = 0; i < value.path.length; i += 1) {
    const entry: unknown = value.path[i];
    if (typeof entry !== 'string' || !HEX_32_BYTES.test(entry)) return `proof path entry ${i} must be a 64 character hex string`;
  }
  return undefined;
}

function reject(problem: string | undefined): void {
  if (problem !== undefined) throw new Error(problem);
}

// Every string that reaches the terminal can carry input the verifier does
// not control, so strip the characters that could rewrite the visible output.
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/g;

function sanitized(io: VerifyIo): VerifyIo {
  const strip = (line: string) => line.replace(CONTROL_CHARACTERS, '');
  return {
    readFile: (path) => io.readFile(path),
    fetchText: (url) => io.fetchText(url),
    gitCommitExists: (repo, commit) => io.gitCommitExists(repo, commit),
    stdout: (line) => io.stdout(strip(line)),
    stderr: (line) => io.stderr(strip(line)),
  };
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

interface Inputs {
  receipt: Receipt;
  registryKeys: PublicJwk[];
  keySource: string;
  root?: RootDocument;
  proof?: RootProof;
}

async function readJson(io: VerifyIo, location: string): Promise<unknown> {
  const text = isUrl(location) ? await io.fetchText(location) : await io.readFile(location);
  return JSON.parse(text) as unknown;
}

async function readInputs(parsed: ParsedArgs, io: VerifyIo): Promise<Inputs> {
  const rawReceipt = await readJson(io, parsed.receipt);
  reject(receiptProblem(rawReceipt));
  const receipt = rawReceipt as Receipt;

  // Every registry entry has to be checked, so every registry's key has to be
  // available. Loading only the first one made a receipt countersigned by two
  // registries always fail, since the second key could never be found.
  let registryKeys: PublicJwk[] = [];
  const sources: string[] = [];
  const hints = parsed.jwks !== undefined
    ? [parsed.jwks]
    : parsed.offline
      ? []
      : [...new Set(registrySignaturesOf(receipt).map((entry) => entry.jwks).filter((jwks): jwks is string => typeof jwks === 'string'))];
  for (const location of hints) {
    if (parsed.offline && isUrl(location)) throw new Error(`--offline forbids fetching ${location}`);
    const rawJwks = await readJson(io, location);
    reject(jwksProblem(rawJwks));
    registryKeys = [...registryKeys, ...(rawJwks as { keys: PublicJwk[] }).keys];
    sources.push(location);
  }
  const keySource = sources.length === 0 ? 'none' : sources.join(', ');

  const inputs: Inputs = { receipt, registryKeys, keySource };
  if (parsed.root !== undefined && parsed.proof !== undefined) {
    const rawRoot = await readJson(io, parsed.root);
    reject(rootProblem(rawRoot));
    const rawProof = await readJson(io, parsed.proof);
    reject(proofProblem(rawProof));
    inputs.root = rawRoot as RootDocument;
    inputs.proof = rawProof as RootProof;
  }
  return inputs;
}

// Everything here is read defensively. This check runs alongside
// verifyReceipt rather than after it, so it sees receipts whose shape has
// already failed, and the specification requires a verdict for any input
// rather than an exception. A null in outputs used to throw here.
async function commitBinding(receipt: Receipt, repo: string | undefined, io: VerifyIo): Promise<Check> {
  const name = 'commit_binding';
  const action: unknown = (receipt as { action?: unknown }).action;
  if (!isObject(action)) return { name, status: 'skip', detail: 'action is not an object' };
  const type = action.type;
  if (type !== 'git.commit') return { name, status: 'skip', detail: `action ${typeof type === 'string' ? type.slice(0, 40) : JSON.stringify(type)} is not a commit` };
  const commit = action.commit;
  if (typeof commit !== 'string' || !COMMIT_HASH.test(commit)) return { name, status: 'fail', detail: 'commit hash missing or malformed' };
  const outputs: unknown = (receipt as { outputs?: unknown }).outputs;
  const listed = Array.isArray(outputs)
    && outputs.some((output) => isObject(output) && output.kind === 'commit' && output.ref === commit);
  if (!listed) return { name, status: 'fail', detail: 'commit is not among the outputs' };
  const files = action.files_changed;
  const suffix = Number.isInteger(files) ? ` (${String(files)} files)` : '';
  if (repo !== undefined) {
    const exists = await io.gitCommitExists(repo, commit);
    if (!exists) return { name, status: 'fail', detail: `commit ${commit} not found in ${repo}` };
    return { name, status: 'pass', detail: `${commit.slice(0, 7)} exists in ${repo}${suffix}` };
  }
  return { name, status: 'pass', detail: `${commit.slice(0, 7)}${suffix}` };
}

function rootInclusion(receipt: Receipt, root: RootDocument, proof: RootProof, keys: Map<string, PublicJwk>): Check {
  const name = 'root_inclusion';
  if (!verifyRoot(root, keys)) return { name, status: 'fail', detail: 'root signature does not verify' };
  if (!verifyRootInclusion(receipt, proof, root)) return { name, status: 'fail', detail: 'receipt is not included in the root' };
  return { name, status: 'pass', detail: `${root.date} sequence ${root.sequence_start} to ${root.sequence_end}` };
}

const LABELS: Record<string, string> = {
  integrity: 'Receipt integrity',
  agent_signature: 'Agent signature',
  agent_identity: 'Agent identity',
  registry_signature: 'Registry signature',
  commit_binding: 'Commit binding',
  root_inclusion: 'Root inclusion',
};

const MARKERS: Record<CheckStatus, string> = { pass: '✓', fail: '✗', skip: '-' };

// A receipt countersigned by more than one registry reports one numbered
// check per registry, in the order the entries appear in the receipt.
const NUMBERED_REGISTRY = /^registry_signature_(\d{1,3})$/;

function labelOf(check: Check): string {
  const known = LABELS[check.name];
  if (known !== undefined) return known;
  const numbered = NUMBERED_REGISTRY.exec(check.name);
  if (numbered) return `Registry signature ${numbered[1]}`;
  const role = check.name.replace(/_signature$/, '');
  return `${role.charAt(0).toUpperCase()}${role.slice(1)} signature`;
}

function render(check: Check): string {
  return `${MARKERS[check.status]} ${labelOf(check).padEnd(23)}${check.detail}`;
}

async function runChecks(parsed: ParsedArgs, inputs: Inputs, io: VerifyIo): Promise<number> {
  const keys = keyMapFromJwks(inputs.registryKeys);
  const result = verifyReceipt(inputs.receipt, { registryKeys: keys });
  const checks: Check[] = [...result.checks];
  checks.push(await commitBinding(inputs.receipt, parsed.repo, io));
  if (inputs.root !== undefined && inputs.proof !== undefined) {
    checks.push(rootInclusion(inputs.receipt, inputs.root, inputs.proof, keys));
  }
  const ok = checks.every((check) => check.status !== 'fail');

  if (parsed.json) {
    io.stdout(JSON.stringify({ ok, receipt: inputs.receipt.id, agent: inputs.receipt.agent, key_source: inputs.keySource, checks }, null, 2));
  } else {
    for (const check of checks) io.stdout(render(check));
    io.stdout(ok ? 'VERIFIED' : 'FAILED');
  }
  return ok ? 0 : 1;
}

export async function runVerify(args: string[], rawIo: VerifyIo): Promise<number> {
  const io = sanitized(rawIo);
  const parsed = parseArgs(args);
  if (typeof parsed === 'string') {
    io.stderr(parsed);
    io.stderr(VERIFY_USAGE);
    return 2;
  }

  let inputs: Inputs;
  try {
    inputs = await readInputs(parsed, io);
  } catch (error) {
    io.stderr(`cannot read input: ${messageOf(error)}`);
    return 2;
  }

  try {
    return await runChecks(parsed, inputs, io);
  } catch (error) {
    io.stderr(`internal error: ${messageOf(error)}`);
    return 2;
  }
}

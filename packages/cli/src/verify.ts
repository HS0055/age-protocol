import {
  canonicalBytes, isPublicJwk, keyMapFromJwks, verifyBytes, verifyChain, verifyInclusion, verifyReceipt, ROOT_TYP,
  type InclusionProof, type PublicJwk, type Receipt,
} from '@agie/receipts';

export interface VerifyIo {
  readFile(path: string): Promise<string>;
  stdout(line: string): void;
  stderr(line: string): void;
}

export const VERIFY_USAGE = 'usage: agie verify <receipt.json> --jwks <jwks.json> [--chain <receipts.json>] [--root <root.json> --proof <proof.json>]';

const KNOWN_FLAGS = ['jwks', 'chain', 'root', 'proof'];

interface ParsedArgs {
  receipt: string;
  jwks: string;
  chain?: string;
  root?: string;
  proof?: string;
}

function parseArgs(args: string[]): ParsedArgs | string {
  const positional: string[] = [];
  const flags: Record<string, string> = {};
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i] as string;
    if (arg.startsWith('--')) {
      const name = arg.slice(2);
      if (!KNOWN_FLAGS.includes(name)) return `unknown flag: ${arg}`;
      const value = args[i + 1];
      if (value === undefined || value.startsWith('--')) return `missing value for ${arg}`;
      flags[name] = value;
      i += 1;
    } else {
      positional.push(arg);
    }
  }
  if (positional.length !== 1) return 'expected exactly one receipt file';
  if (!flags.jwks) return '--jwks is required';
  if ((flags.root && !flags.proof) || (flags.proof && !flags.root)) return '--root and --proof must be given together';
  return { receipt: positional[0] as string, jwks: flags.jwks, chain: flags.chain, root: flags.root, proof: flags.proof };
}

async function readJson(io: VerifyIo, path: string): Promise<unknown> {
  return JSON.parse(await io.readFile(path)) as unknown;
}

interface RootDoc {
  typ: string;
  date: string;
  size: number;
  root: string;
  cloud: { jkt: string };
  sig: string;
}

// Input shapes are checked before any verification runs, so a malformed file
// is an input error with a message and never an exception out of a check.

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

const HEX_32_BYTES = /^[0-9a-fA-F]{64}$/;

function receiptProblem(value: unknown, label: string): string | undefined {
  if (!isObject(value)) return `${label} must be an object`;
  if (typeof value.typ !== 'string') return `${label} has no typ`;
  if (typeof value.id !== 'string') return `${label} id must be a string`;
  const node = value.node;
  if (node !== null && !(isObject(node) && typeof node.jkt === 'string')) {
    return `${label} node must be null or an object with a jkt string`;
  }
  if (!(isObject(value.cloud) && typeof value.cloud.jkt === 'string')) {
    return `${label} cloud must be an object with a jkt string`;
  }
  if (typeof value.cloud_sig !== 'string') return `${label} cloud_sig must be a string`;
  return undefined;
}

function jwksProblem(value: unknown): string | undefined {
  if (!isObject(value) || !Array.isArray(value.keys)) return 'jwks file has no keys array';
  for (let i = 0; i < value.keys.length; i += 1) {
    if (!isPublicJwk(value.keys[i])) return `jwks key ${i} is not a public JWK`;
  }
  return undefined;
}

function chainProblem(value: unknown): string | undefined {
  if (!Array.isArray(value)) return 'chain file must be an array of receipts';
  for (let i = 0; i < value.length; i += 1) {
    const problem = receiptProblem(value[i], `chain receipt ${i}`);
    if (problem !== undefined) return problem;
  }
  return undefined;
}

function rootProblem(value: unknown): string | undefined {
  if (!isObject(value)) return 'root file must be an object';
  if (typeof value.typ !== 'string') return 'root file has no typ';
  if (typeof value.date !== 'string') return 'root file date must be a string';
  if (!Number.isInteger(value.size)) return 'root file size must be an integer';
  if (typeof value.root !== 'string') return 'root file root must be a string';
  if (!(isObject(value.cloud) && typeof value.cloud.jkt === 'string')) return 'root file has no cloud.jkt';
  if (typeof value.sig !== 'string') return 'root file sig must be a string';
  return undefined;
}

function proofProblem(value: unknown): string | undefined {
  if (!isObject(value)) return 'proof file must be an object';
  if (!Number.isInteger(value.index)) return 'proof index must be an integer';
  if (!Number.isInteger(value.size)) return 'proof size must be an integer';
  if (!Array.isArray(value.path)) return 'proof path must be an array';
  for (let i = 0; i < value.path.length; i += 1) {
    const entry: unknown = value.path[i];
    if (typeof entry !== 'string' || !HEX_32_BYTES.test(entry)) {
      return `proof path entry ${i} must be a 64 character hex string`;
    }
  }
  return undefined;
}

function reject(problem: string | undefined): void {
  if (problem !== undefined) throw new Error(problem);
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

interface Inputs {
  receipt: Receipt;
  keys: PublicJwk[];
  chain?: Receipt[];
  root?: RootDoc;
  proof?: InclusionProof;
}

async function readInputs(parsed: ParsedArgs, io: VerifyIo): Promise<Inputs> {
  const rawReceipt = await readJson(io, parsed.receipt);
  reject(receiptProblem(rawReceipt, 'receipt'));

  const rawJwks = await readJson(io, parsed.jwks);
  reject(jwksProblem(rawJwks));

  const inputs: Inputs = {
    receipt: rawReceipt as Receipt,
    keys: (rawJwks as { keys: PublicJwk[] }).keys,
  };

  if (parsed.chain !== undefined) {
    const rawChain = await readJson(io, parsed.chain);
    reject(chainProblem(rawChain));
    inputs.chain = rawChain as Receipt[];
  }
  if (parsed.root !== undefined) {
    const rawRoot = await readJson(io, parsed.root);
    reject(rootProblem(rawRoot));
    inputs.root = rawRoot as RootDoc;
  }
  if (parsed.proof !== undefined) {
    const rawProof = await readJson(io, parsed.proof);
    reject(proofProblem(rawProof));
    inputs.proof = rawProof as InclusionProof;
  }
  return inputs;
}

function runChecks(parsed: ParsedArgs, inputs: Inputs, io: VerifyIo): number {
  const { receipt, keys, chain, root, proof } = inputs;
  let failed = false;
  const byThumbprint = keyMapFromJwks(keys);
  io.stdout(`receipt  ${receipt.id}`);

  const signatures = verifyReceipt(receipt, byThumbprint);
  io.stdout(`node     ${signatures.node}`);
  io.stdout(`cloud    ${signatures.cloud}`);
  for (const error of signatures.errors) io.stderr(error);
  if (!signatures.ok) failed = true;

  // Keyed on the flags, so a check the user asked for either runs or is an
  // input error. It can never be silently skipped.
  if (parsed.chain !== undefined) {
    if (chain === undefined) throw new Error('chain file was requested but not loaded');
    const last = chain[chain.length - 1];
    if (!last || last.id !== receipt.id || last.cloud_sig !== receipt.cloud_sig) {
      io.stderr('receipt is not the last element of the chain file');
      io.stdout('chain    invalid');
      failed = true;
    } else {
      const result = verifyChain(chain);
      io.stdout(result.ok ? `chain    valid (${result.length} receipts)` : 'chain    invalid');
      for (const error of result.errors) io.stderr(error);
      if (!result.ok) failed = true;
    }
  } else {
    io.stdout('chain    skipped');
  }

  if (parsed.root !== undefined) {
    if (root === undefined || proof === undefined) throw new Error('root file was requested but not loaded');
    const cloudKey = byThumbprint.get(root.cloud.jkt);
    const rootBytes = canonicalBytes({ typ: ROOT_TYP, date: root.date, size: root.size, root: root.root });
    if (root.typ !== ROOT_TYP) {
      io.stderr(`root document typ ${root.typ} is not ${ROOT_TYP}`);
      io.stdout('root     invalid');
      failed = true;
    } else if (!cloudKey) {
      io.stderr(`root cloud key ${root.cloud.jkt} not in key set`);
      io.stdout('root     unknown_key');
      failed = true;
    } else if (!verifyBytes(rootBytes, root.sig, cloudKey)) {
      io.stderr('root signature does not verify');
      io.stdout('root     invalid');
      failed = true;
    } else if (!verifyInclusion(canonicalBytes(receipt), proof, root.root)) {
      io.stderr('receipt is not included in the published root');
      io.stdout('root     not included');
      failed = true;
    } else {
      io.stdout(`root     valid (${root.date}, size ${root.size}, included)`);
    }
  } else {
    io.stdout('root     skipped');
  }

  io.stdout(failed ? 'result   FAILED' : 'result   verified');
  return failed ? 1 : 0;
}

export async function runVerify(args: string[], io: VerifyIo): Promise<number> {
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
    return runChecks(parsed, inputs, io);
  } catch (error) {
    io.stderr(`internal error: ${messageOf(error)}`);
    return 2;
  }
}

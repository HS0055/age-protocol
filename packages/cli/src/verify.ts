import {
  canonicalBytes, verifyBytes, verifyChain, verifyInclusion, verifyReceipt, ROOT_TYP,
  type InclusionProof, type PublicJwk, type Receipt,
} from '@agie/receipts';

export interface VerifyIo {
  readFile(path: string): Promise<string>;
  stdout(line: string): void;
  stderr(line: string): void;
}

export const VERIFY_USAGE = 'usage: agie verify <receipt.json> --jwks <jwks.json> [--chain <receipts.json>] [--root <root.json> --proof <proof.json>]';

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
      const value = args[i + 1];
      if (value === undefined || value.startsWith('--')) return `missing value for ${arg}`;
      flags[arg.slice(2)] = value;
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

async function readJson<T>(io: VerifyIo, path: string): Promise<T> {
  return JSON.parse(await io.readFile(path)) as T;
}

interface RootDoc {
  typ: string;
  date: string;
  size: number;
  root: string;
  cloud: { jkt: string };
  sig: string;
}

export async function runVerify(args: string[], io: VerifyIo): Promise<number> {
  const parsed = parseArgs(args);
  if (typeof parsed === 'string') {
    io.stderr(parsed);
    io.stderr(VERIFY_USAGE);
    return 2;
  }

  let receipt: Receipt;
  let keys: PublicJwk[];
  let chain: Receipt[] | undefined;
  let root: RootDoc | undefined;
  let proof: InclusionProof | undefined;
  try {
    receipt = await readJson<Receipt>(io, parsed.receipt);
    keys = (await readJson<{ keys: PublicJwk[] }>(io, parsed.jwks)).keys;
    if (!Array.isArray(keys)) throw new Error('jwks file has no keys array');
    if (parsed.chain) chain = await readJson<Receipt[]>(io, parsed.chain);
    if (parsed.root) {
      root = await readJson<RootDoc>(io, parsed.root);
      if (
        typeof root !== 'object' || root === null ||
        typeof root.cloud !== 'object' || root.cloud === null ||
        typeof root.cloud.jkt !== 'string'
      ) {
        throw new Error('root file has no cloud.jkt');
      }
    }
    if (parsed.proof) proof = await readJson<InclusionProof>(io, parsed.proof);
  } catch (error) {
    io.stderr(`cannot read input: ${(error as Error).message}`);
    return 2;
  }

  let failed = false;
  io.stdout(`receipt  ${receipt.id}`);

  const signatures = verifyReceipt(receipt, keys);
  io.stdout(`node     ${signatures.node}`);
  io.stdout(`cloud    ${signatures.cloud}`);
  for (const error of signatures.errors) io.stderr(error);
  if (!signatures.ok) failed = true;

  if (chain) {
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

  if (root && proof) {
    const cloudKey = keys.find((key) => key.kid === root.cloud.jkt);
    const rootBytes = canonicalBytes({ typ: ROOT_TYP, date: root.date, size: root.size, root: root.root });
    if (root.typ !== ROOT_TYP) {
      io.stderr(`root document typ ${String(root.typ)} is not ${ROOT_TYP}`);
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

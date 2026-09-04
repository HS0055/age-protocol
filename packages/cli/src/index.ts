import { readFile } from 'node:fs/promises';
import { runVerify, VERIFY_USAGE } from './verify.ts';

const USAGE = ['usage: agie <command>', '', 'commands:', '  verify   verify a receipt offline', '', VERIFY_USAGE].join('\n');

export async function main(argv: string[]): Promise<number> {
  const [command, ...rest] = argv;
  const io = {
    readFile: (path: string) => readFile(path, 'utf8'),
    stdout: (line: string) => console.log(line),
    stderr: (line: string) => console.error(line),
  };
  switch (command) {
    case 'verify':
      return runVerify(rest, io);
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

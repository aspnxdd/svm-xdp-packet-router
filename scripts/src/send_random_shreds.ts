import { randomBytes, randomInt } from "node:crypto";

const SHRED_DATA_BYTES = 1024;
const MAX_WITNESS_LEN = 8;
const COMMITMENT_BYTES = 32;
const WITNESS_BYTES = 32 * MAX_WITNESS_LEN;
const PROPOSER_SIG_BYTES = 64;
const TAIL_PADDING_BYTES = 7;
const XSK_MAX_QUEUES = 64;

const SHRED_WIRE_LEN =
  8 +
  4 +
  4 +
  COMMITMENT_BYTES +
  SHRED_DATA_BYTES +
  1 +
  WITNESS_BYTES +
  PROPOSER_SIG_BYTES +
  TAIL_PADDING_BYTES;

type Args = {
  count: number;
  verbose: boolean;
};

type ShredInfo = {
  slot: bigint;
  proposerIndex: number;
  shredIndex: number;
  expectedQueue: number;
  payload: Buffer;
};

const args = parseArgs(process.argv.slice(2));

function main(): void {
  for (let index = 0; index < args.count; index += 1) {
    const shred = makeRandomShred(index);

    if (args.verbose) {
      console.error(
        [
          `len=${shred.payload.length}`,
          `slot=${shred.slot}`,
          `proposer_index=${shred.proposerIndex}`,
          `shred_index=${shred.shredIndex}`,
          `expected_queue=${shred.expectedQueue}`,
        ].join(" "),
      );
    }

    console.log(shred.payload.toString("hex"));
  }
}

main();

function parseArgs(argv: string[]): Args {
  const verbose = argv.includes("--verbose") || argv.includes("-v");
  const countArg = argv.find((arg) => !arg.startsWith("-"));
  const count = countArg ? Number(countArg) : 1;

  if (!Number.isInteger(count) || count <= 0) {
    usage(`invalid count: ${countArg}`);
  }

  return { count, verbose };
}

function usage(message: string): never {
  console.error(message);
  console.error(
    "usage: npx tsx scripts/send_random_shreds.ts [count] [--verbose]",
  );
  console.error(
    'send one: ./send_udp.sh 127.0.0.1 8001 "$(npx tsx scripts/send_random_shreds.ts)"',
  );
  console.error("inspect:  npx tsx scripts/send_random_shreds.ts --verbose");
  process.exit(1);
}

function makeRandomShred(shredIndex: number): ShredInfo {
  const slot = randomBigUint64();
  const proposerIndex = randomInt(0, 2 ** 32);
  const expectedQueue = proposerIndex % XSK_MAX_QUEUES;
  const payload = Buffer.alloc(SHRED_WIRE_LEN);
  let offset = 0;

  payload.writeBigUInt64BE(slot, offset);
  offset += 8;

  payload.writeUInt32BE(proposerIndex, offset);
  offset += 4;

  payload.writeUInt32BE(shredIndex, offset);
  offset += 4;

  offset = writeRandom(payload, offset, COMMITMENT_BYTES);
  offset = writeRandom(payload, offset, SHRED_DATA_BYTES);

  payload.writeUInt8(MAX_WITNESS_LEN, offset);
  offset += 1;

  offset = writeRandom(payload, offset, WITNESS_BYTES);
  offset = writeRandom(payload, offset, PROPOSER_SIG_BYTES);

  // repr(C) adds tail padding because Shred is aligned to the u64 slot field.
  offset += TAIL_PADDING_BYTES;

  if (offset !== SHRED_WIRE_LEN) {
    throw new Error(
      `internal error: payload len ${offset}, expected ${SHRED_WIRE_LEN}`,
    );
  }

  return {
    slot,
    proposerIndex,
    shredIndex,
    expectedQueue,
    payload,
  };
}

function randomBigUint64(): bigint {
  return randomBytes(8).readBigUInt64BE();
}

function writeRandom(buffer: Buffer, offset: number, length: number): number {
  randomBytes(length).copy(buffer, offset);
  return offset + length;
}

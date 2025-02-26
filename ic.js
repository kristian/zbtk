import { Buffer } from 'node:buffer';

import { ic as format } from './format.js';
import { crc, mmo } from './hash.js';

export const iclen = 16;
export const crclen = 2;

/**
 * Validate the given Install Code (ic) by checking the CRC checksum.
 *
 * @param {Buffer} ic the Install Code to validate
 * @returns {boolean} true if the Install Code is valid
 */
export function validate(ic) {
  if (ic.length === iclen) {
    throw new TypeError('Incomplete Install Code / missing CRC checksum');
  } else if (ic.length !== (iclen + crclen)) {
    throw new TypeError(`Invalid length of Install Code expected ${iclen} + ${crclen} CRC, got ${ic.length}`);
  }

  return crc(ic.subarray(0, iclen)).equals(ic.subarray(iclen));
}

/**
 * Calculate the CRC checksum for the given Install Code (ic).
 *
 * @param {Buffer} ic the Install Code to calculate the CRC checksum for
 * @param {boolean} [full=true] whether to return the full Install Code with the CRC checksum or just the CRC checksum
 * @returns {Buffer} the CRC checksum for the Install Code (ic)
 */
export function checksum(ic, full = true) {
  if (ic.length === (iclen + crclen)) {
    return full ? ic : ic.subarray(iclen); // already contains a CRC checksum
  } else if (ic.length !== iclen) {
    throw new TypeError(`Invalid length of Install Code expected ${iclen} bytes, got ${ic.length}`);
  }

  return full ? Buffer.concat([ic, crc(ic)]) : crc(ic);
}

export { format };

/**
 * Calculate the Link Key for the given Install Code (ic).
 *
 * As per specification of the ZigBee Certificate-Based Key Establishment (CBKE), the
 * Link Key (lk) for a given Install Code (ic) is calculated by applying the
 * Matyas-Meyer-Oseas (AES-MMO) hash function hash function to the Install Code.
 *
 * @param {Buffer} ic the Install Code to calculate the Link Key for
 * @returns {Buffer} the Link Key for the Install Code (ic)
 */
export function link(ic) {
  return mmo(checksum(ic));
}

import { moduleHandler, stdinMiddleware } from './utils.js';
export const command = {
  command: 'ic <action> [install-code]',
  desc: 'Install Code Utilities',
  builder: yargs => stdinMiddleware(yargs
    .positional('action', {
      desc: 'Action to perform',
      type: 'string',
      choices: ['validate', 'checksum', 'format', 'link']
    }), 'install-code', { desc: 'Install Code to process', alias: 'ic' })
    .example('$0 ic validate 83fed3407a939723a5c639b26916d505c3b5', 'Validate the given Install Code')
    .example('$0 ic checksum 83fed3407a939723a5c639b26916d505', 'Calculate the CRC checksum for the given Install Code')
    .example('$0 ic format 83fed3407a939723a5c639b26916d505c3b5', 'Format the given Install Code')
    .example('$0 ic link 83fed3407a939723a5c639b26916d505c3b5', 'Calculate the Link Key for the given Install Code')
    .version(false)
    .help(),
  handler: moduleHandler(import.meta.url, 'action', 'ic', (out, argv) => {
    if (argv.action === 'validate') {
      console.log(out);
      process.exit(out ? 0 : 1);
    }

    return out.toString('hex');
  })
};

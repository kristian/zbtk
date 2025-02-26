import { Buffer } from 'node:buffer';
import crypto from 'crypto';

const blockSize = 16;
const keySize = 16;

/*
  Template from https://gist.github.com/bryc/79d1a62304773285317191f1ae5aa5b8
  Copyright by bryc (https://gist.github.com/bryc)

  Adapted to ZigBee (default to CRC-16/IBM-SDLC and using Buffers)
*/

/**
 * Optimized CRC-16 for 0x1021 (reflected)
 * ----
 * Note: The actual polynomial being used is 0x8408, as it has been reflected.
 * With this code, (6) CRC-16 variants can be modelled:
 * crc=0x0000, xorout=0x0000 = CRC-16/KERMIT, aka CRC-16/CCITT (default)
 * crc=0xFFFF, xorout=0x0000 = CRC-16/MCRF4XX
 * crc=0xFFFF, xorout=0xFFFF = CRC-16/IBM-SDLC
 * crc=0x554d, xorout=0x0000 = CRC-16/RIELLO
 * crc=0x3791, xorout=0x0000 = CRC-16/TMS37157
 * crc=0x6363, xorout=0x0000 = CRC-16/ISO-IEC-14443-3-A
 * Note: The bits of the initial crc value must be in reverse order.
 * The values supplied have been reversed above.
 *
 * @param {Buffer} data the data to calculate the hash for
 * @param {number} [crc] the CRC value to start with
 * @param {number} [xorout] the XOR value to use
 * @returns {Buffer} two bytes buffer representing the CRC-16 checksum
 */
export function crc(data, crc = 0xFFFF, xorout = 0xFFFF) {
  for (let i = 0, t; i < data.length; i++, crc &= 0xFFFF) {
    t = (crc) ^ data[i];
    t = (t ^ t << 4) & 0xFF;
    crc = (crc >> 8) ^ (t << 8) ^ (t >> 4) ^ (t << 3);
  }

  const b = Buffer.alloc(2);
  b.writeUint16LE(crc ^ xorout);
  return b;
}

/*
  Template from https://github.com/andrebdo/c-crumbs/blob/master/aes-mmo.h
  Under public domain by andrebdo (https://github.com/andrebdo)

  Adapted to NodeJS / ECMAscript
*/

function aesEncrypt(keyBuffer, inBuffer, outBuffer) {
  const cipher = crypto.createCipheriv('aes-128-ecb', keyBuffer, null);
  cipher.setAutoPadding(false);
  const encBuffer = cipher.update(inBuffer);
  encBuffer.copy(outBuffer, 0, 0, blockSize);
}

/*
  aes-mmo.h: AES Matyas-Meyer-Oseas (AES-MMO) hash function

  https://github.com/andrebdo/c-crumbs/blob/master/aes-mmo.h

  This is free and unencumbered software released into the public domain.
  For more information, please refer to UNLICENSE or http://unlicense.org
*/

/**
 * Computes the Matyas-Meyer-Oseas hash function based on the AES-128 block cipher.
 *
 * Reference:
 *  ZigBee specification, document 05-3474-21, Aug 2015,
 *  section B.6 Block-Cipher-Based Cryptographic Hash Function.
 *
 * @param {Buffer} data the data to calculate the Matyas-Meyer-Oseas (MMO) Hash for
 * @returns {Buffer} the Matyas-Meyer-Oseas (MMO) Hash of the data
 */
export function mmo(data) {
  // Initialize digest to 0^(8n) (n-octet all-zero bit string)
  const digest = Buffer.alloc(blockSize);
  digest.fill(0);

  // Process blocks of 16 bytes: Hashj = E(Hashj-1, Mj) xor Mj
  for (let r = 0; r <= data.length - 16; r += blockSize) {
    aesEncrypt(digest, data.subarray(r, r + blockSize), digest);
    for (let i = 0; i < blockSize; i++) {
      digest[i] ^= data[r + i];
    }
  }

  // Build and process the final padded block(s)
  const p = Buffer.alloc(blockSize);
  let r = data.length % blockSize;
  for (let i = 0; i < r; i++) {
    p[i] = data[(data.length & ~15) + i];
  }
  p[r++] = 0x80;

  if ((data.length < 8192 && r > 14) || (data.length >= 8192 && r > 10)) {
    // First of two padded blocks
    for (let i = r; i < blockSize; i++) {
      p[i] = 0;
    }
    aesEncrypt(digest, p, digest);
    for (let i = 0; i < blockSize; i++) {
      digest[i] ^= p[i];
    }
    r = 0;
  }

  // Final padded block with length in bits
  if (data.length < 8192) {
    for (let i = r; i < 14; i++) {
      p[i] = 0;
    }
    p[14] = data.length >> 5;
    p[15] = data.length << 3;
  } else {
    for (let i = r; i < 10; i++) {
      p[i] = 0;
    }
    p[10] = data.length >> 21;
    p[11] = data.length >> 13;
    p[12] = data.length >> 5;
    p[13] = data.length << 3;
    p[14] = 0;
    p[15] = 0;
  }

  aesEncrypt(digest, p, digest);
  for (let i = 0; i < blockSize; i++) {
    digest[i] ^= p[i];
  }

  return digest;
}

/*
  Adapted from Wireshark. See zbee_sec_key_hash in
  https://github.com/boundary/wireshark/blob/master/epan/dissectors/packet-zbee-security.c
*/

/**
 * ZigBee Keyed Hash Function. Described in ZigBee specification
 * section B.1.4, and in FIPS Publication 198. Strictly speaking
 * there is nothing about the Keyed Hash Function which restricts
 * it to only a single byte input, but that's all ZigBee ever uses.
 *
 * This function implements the hash function:
 *    Hash(Key, text) = H((Key XOR opad) || H((Key XOR ipad) || text));
 *    ipad = 0x36 repeated.
 *    opad = 0x5c repeated.
 *    H() = ZigBee Cryptographic Hash (B.1.3 and B.6).
 *
 * @param {Buffer} data the key data to hash, must be 16 bytes in length
 * @param {(Buffer|number)} [input=0x0] the CCM* nonce
 * @returns {Buffer} the hash of the key
 */
export function key(data, input = 0x0) {
  if (typeof input === 'number') {
    const inputb = Buffer.allocUnsafe(2);
    inputb.writeUInt8(input);
    input = inputb;
  }

  const hashOut = Buffer.alloc(blockSize + 1);
  const hashIn = Buffer.alloc(2 * blockSize);

  const ipad = 0x36, opad = 0x5c;

  // copy the key into hash_in and XOR with opad to form: (Key XOR opad)
  for (let i = 0; i < keySize; i++) hashIn[i] = data[i] ^ opad;
  // copy the Key into hash_out and XOR with ipad to form: (Key XOR ipad)
  for (let i = 0; i < keySize; i++) hashOut[i] = data[i] ^ ipad;

  // append the input byte to form: (Key XOR ipad) || text
  input.copy(hashOut, blockSize);

  // Hash the contents of hash_out and append the contents to hash_in to
  // form: (Key XOR opad) || H((Key XOR ipad) || text)
  mmo(hashOut).copy(hashIn, blockSize);

  // Hash the contents of hash_in to get the final result
  return mmo(hashIn);
}

import { moduleHandler, stdinMiddleware } from './utils.js';
export const command = {
  command: 'hash [type] [data]',
  desc: 'Hash / Checksum Calculation',
  builder: yargs => stdinMiddleware(yargs
    .positional('type', {
      desc: 'Type of hash / checksum to calculate',
      type: 'string',
      choices: ['crc', 'mmo', 'key']
    }), { desc: 'Data to calculate hash / checksum for' })
    .option('input', {
      alias: 'i',
      desc: 'Input nonce for key-based MMO hash',
      type: 'number'
    })
    .example('$0 crc 83fed3407a939723a5c639b26916d505', 'Calculate the CRC-16 checksum for the given data')
    .example('$0 mmo 83fed3407a939723a5c639b26916d505c3b5', 'Calculate the Matyas-Meyer-Oseas (MMO) Hash of the given data')
    .example('$0 key 66b6900981e1ee3ca4206b6b861c02bb --input 0', 'Calculate a key-based MMO hash, with the given input nonce')
    .example('echo -n 83fed3407a939723a5c639b26916d505 | $0 crc', 'Use the non-streamed standard input to calculate the CRC-16')
    .version(false)
    .help(),
  handler: moduleHandler(import.meta.url, 'type', argv => argv.type !== 'key' ? [argv.data] : [argv.data, argv.input || 0x0])
};

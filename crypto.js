import crypto from 'crypto';
import { Buffer } from 'node:buffer';
import { fromHex, toHex } from './utils.js';

const alg = 'aes-128-ccm';

// pre-configured keys
export const pks = (!process.env.ZBTK_CRYPTO_WELL_KNOWN_PKS ? [] : [
  fromHex('D0:D1:D2:D3:D4:D5:D6:D7:D8:D9:DA:DB:DC:DD:DE:DF'), // Uncertified
  fromHex('5A:69:67:42:65:65:41:6C:6C:69:61:6E:63:65:30:39') // ZigBeeAlliance09
]).concat(!process.env.ZBTK_CRYPTO_PKS ? [] : process.env.ZBTK_CRYPTO_PKS.split('[,; ]').map(fromHex));

/**
 * Pre-configure a network key to be used for automatic decryption.
 *
 * @param {(string|Buffer)} key the key to pre-configure
 * @returns {boolean} true if the key was added, false if it was already present
 */
export function pk(key) {
  if (!Buffer.isBuffer(key)) {
    key = fromHex(key);
  }

  return !!(!pks.some(c => c.equals(key)) && pks.push(key));
}

function prepare(src64, fc, scf, aad) {
  if (!process.env.ZBTK_CRYPTO_NO_WIRE_WORKAROUND) {
    // the security control field is not filled in correctly in the header,
    // so it is necessary to patch it up to contain ZBEE_SEC_ENC_MIC32 == 5.
    // not sure why, but Wireshark does it. also patch it in the AAD header.
    // the aad is 22 bytes in length, or 30 / 38 in case of a ext src+/dst.
    let idx;
    if (aad.length == 15) { // APS header
      idx = 2;
    } else { // NWK header
      idx = 8 + (aad.length - 22);
    }

    // just a safety-safe: check if the SCF is at the position we expect it to be
    if (aad[idx] !== scf[0]) {
      throw new Error(`Mismatch in AAD crypto. data for Wireshark workaround, expected SCF ${toHex(scf[0])} at position ${idx} of AAD, but got ${toHex(aad[idx])}`);
    }

    aad[idx] = scf[0] = (scf[0] & ~0x07) | 0x05;
  }

  if (typeof fc === 'number') {
    const fcb = Buffer.allocUnsafe(4);
    fcb.writeUInt32LE(fc);
    fc = fcb;
  }

  return {
    // according to the ZigBee Specification the iv for the encryption is a concatenation of the
    // src64 (extended source), fc (frame counter) and scf (security control field)
    nonce: Buffer.concat([src64, fc, scf])
  };
}

/**
 * Encrypts the given data using the Network Key (nk) and parameters.
 *
 * With help of https://github.com/osresearch/ZbPy/blob/master/zbdecode
 * https://lucidar.me/en/zigbee/zigbee-frame-encryption-with-aes-128-ccm/
 * https://lucidar.me/en/zigbee/autopsy-of-a-zigbee-frame/#nwk-payload
 *
 * @param {Buffer} data the data to encrypt
 * @param {Buffer} nk Network Key, e.g. the temporary Link Key (lk) based on the Install Code (ic), the
 *   Transport Key as captured during Device Association or the well-known default
 *   Link Key aka ZigBee Transport Key aka ZigBeeAlliance09 (5A:69:67:62:65:65:41:6C:6C:69:61:6E:63:65:30:39)
 * @param {Buffer} src64 extended IEEE address of sender (8 bytes) from the ZigBee Security Header
 * @param {(Buffer|number)} fc Frame Counter (4 bytes) from the ZigBee Security Header
 * @param {Buffer} scf Security Control byte aka Security Control Field (1 byte) first byte in the ZigBee Security Header
 * @param {Buffer} aad Additional Authenticated Data, this includes the full ZigBee Network Layer Data Header (NwkHeader) +
 *   the first part of the ZigBee Security Header aka the auxiliary frame header, more specifically
 *     NwkHeader (Frame Control Field, Destination Address, Source Address, Radius and Sequence Number) +
 *     AuxiliaryHeader (Security Control Field, Frame Counter, Extended Source Address, Key Sequence Number)
 * @param {number} miclen Message Integrity Code from the end of the ZigBee Network Layer Data packet / Security Header
 * @returns {{ data: Buffer, mic: Buffer }} encrypted data and Message Integrity Code (mic)
 */
export function encrypt(data, nk, src64, fc, scf, aad, miclen = 4) {
  const { nonce } = prepare(src64, fc, scf = Buffer.from(scf), aad = Buffer.from(aad));

  const cipher = crypto.createCipheriv(alg, nk, nonce, {
    authTagLength: miclen
  });

  cipher.setAAD(aad, {
    plaintextLength: data.length
  });

  return {
    data: Buffer.concat([cipher.update(data), cipher.final()]),
    mic: cipher.getAuthTag()
  };
}

/**
 * Decrypts the given data using the Network Key (nk) and parameters.
 *
 * With help of https://github.com/osresearch/ZbPy/blob/master/zbdecode
 * https://lucidar.me/en/zigbee/zigbee-frame-encryption-with-aes-128-ccm/
 * https://lucidar.me/en/zigbee/autopsy-of-a-zigbee-frame/#nwk-payload
 *
 * @param {Buffer} data the data to decrypt
 * @param {Buffer} nk Network Key, e.g. the temporary Link Key (lk) based on the Install Code (ic), the
 *   Transport Key as captured during Device Association or the well-known default
 *   Link Key aka ZigBee Transport Key aka ZigBeeAlliance09 (5A:69:67:62:65:65:41:6C:6C:69:61:6E:63:65:30:39)
 * @param {Buffer} src64 extended IEEE address of sender (8 bytes) from the ZigBee Security Header
 * @param {(Buffer|number)} fc Frame Counter (4 bytes) from the ZigBee Security Header
 * @param {Buffer} scf Security Control byte aka Security Control Field (1 byte) first byte in the ZigBee Security Header
 * @param {Buffer} aad Additional Authenticated Data, this includes the full ZigBee Network Layer Data Header (NwkHeader) +
 *   the first part of the ZigBee Security Header aka the auxiliary frame header, more specifically
 *     NwkHeader (Frame Control Field, Destination Address, Source Address, Radius and Sequence Number) +
 *     AuxiliaryHeader (Security Control Field, Frame Counter, Extended Source Address, Key Sequence Number)
 * @param {Buffer} mic Message Integrity Code to verify the integrity of the data
 * @returns {Buffer} the decrypted data
 */
export function decrypt(data, nk, src64, fc, scf, aad, mic) {
  const { nonce } = prepare(src64, fc, scf = Buffer.from(scf), aad = Buffer.from(aad));

  const decipher = crypto.createDecipheriv(alg, nk, nonce, {
    authTagLength: mic.length
  });

  decipher.setAuthTag(mic);
  decipher.setAAD(aad, {
    plaintextLength: data.length
  });

  return Buffer.concat([
    decipher.update(data),
    decipher.final()
  ]);
}

import { dataMiddleware } from './utils.js';
export const commands = [
  {
    command: 'encrypt [data]',
    desc: 'Encrypt Packet',
    builder: yargs => dataMiddleware(yargs
      .option('network-key', {
        alias: 'nk',
        desc: 'Network Key (i.e. temp. Link Key)',
        type: 'string',
        demandOption: true
      })
      .option('ext-address', {
        alias: 'src64',
        desc: 'Extended IEEE Sender Address (8 bytes)',
        type: 'string',
        demandOption: true
      })
      .option('frame-counter', {
        alias: 'fc',
        desc: 'Frame Counter (4 bytes)',
        type: 'string',
        demandOption: true
      })
      .option('sec-ctrl-field', {
        alias: 'scf',
        desc: 'Security Control Field (1 byte)',
        type: 'string',
        demandOption: true
      })
      .option('add-auth-data', {
        alias: 'aad',
        desc: 'Additional Authenticated Data',
        type: 'string',
        demandOption: true
      })
      .option('mic-length', {
        alias: 'mic',
        desc: 'Message Integrity Code Length',
        type: 'number',
        default: 4
      }), { desc: 'Data to encrypt' })
      .middleware(argv => {
        if (argv.help) {
          return;
        }

        argv.nk = Buffer.from(argv.nk, 'hex');
        argv.src64 = Buffer.from(argv.src64, 'hex');
        argv.fc = Buffer.from(argv.fc, 'hex');
        argv.scf = Buffer.from(argv.scf, 'hex');
        argv.aad = Buffer.from(argv.aad, 'hex');
      })
      .example('$0 encrypt --nk 52f0fe8052ebb35907daa243c95a2ff4 --src64 0db123feffa7db28 --fc 148a0700 --scf 28 --aad 48220000777f1e2028148a07000db123feffa7db2800 40020102040101ef0c2112100a014029a806', 'Encrypt the given data')
      .example('echo -n 40020102040101ef0c2112100a014029a806 | $0 encrypt --nk 52f0fe8052ebb35907daa243c95a2ff4 --src64 0db123feffa7db28 --fc 148a0700 --scf 28 --aad 48220000777f1e2028148a07000db123feffa7db2800', 'Decrypt the given data')
      .version(false)
      .help(),
    handler: argv => {
      const { data, mic } = encrypt(argv.data, argv.nk, argv.src64, argv.fc, argv.scf, argv.aad, argv.mic);
      process.stdout.write(`${data.toString('hex')}${mic.toString('hex')}`);
    }
  },
  {
    command: 'decrypt [data]',
    desc: 'Decrypt Packet',
    builder: yargs => dataMiddleware(yargs
      .option('network-key', {
        alias: 'nk',
        desc: 'Network Key (i.e. temp. Link Key)',
        type: 'string',
        demandOption: true
      })
      .option('ext-address', {
        alias: 'src64',
        desc: 'Extended IEEE Sender Address (8 bytes)',
        type: 'string',
        demandOption: true
      })
      .option('frame-counter', {
        alias: 'fc',
        desc: 'Frame Counter (4 bytes)',
        type: 'string',
        demandOption: true
      })
      .option('sec-ctrl-field', {
        alias: 'scf',
        desc: 'Security Control Field (1 byte)',
        type: 'string',
        demandOption: true
      })
      .option('add-auth-data', {
        alias: 'aad',
        desc: 'Additional Authenticated Data',
        type: 'string',
        demandOption: true
      })
      .option('msg-int-code', {
        alias: 'mic',
        desc: 'Message Integrity Code Length',
        type: 'string'
      }), { desc: 'Data to decrypt' })
      .middleware(argv => {
        if (argv.help) {
          return;
        }

        argv.nk = Buffer.from(argv.nk, 'hex');
        argv.src64 = Buffer.from(argv.src64, 'hex');
        argv.fc = Buffer.from(argv.fc, 'hex');
        argv.scf = Buffer.from(argv.scf, 'hex');
        argv.aad = Buffer.from(argv.aad, 'hex');
        argv.mic = Buffer.from(argv.mic, 'hex');
      })
      .example('$0 decrypt --nk 52f0fe8052ebb35907daa243c95a2ff4 --src64 0db123feffa7db28 --fc 148a0700 --scf 28 --aad 48220000777f1e2028148a07000db123feffa7db2800 --mic 1d37730e 4235bf415d82f5f46c205476a2e6e3d23bfa')
      .example('echo -n 4235bf415d82f5f46c205476a2e6e3d23bfa | $0 decrypt --nk 52f0fe8052ebb35907daa243c95a2ff4 --src64 0db123feffa7db28 --fc 148a0700 --scf 28 --aad 48220000777f1e2028148a07000db123feffa7db2800 --mic 1d37730e')
      .version(false)
      .help(),
    handler: argv => {
      process.stdout.write(decrypt(argv.data, argv.nk, argv.src64, argv.fc, argv.scf, argv.aad, argv.mic).toString('hex'));
    }
  }
];

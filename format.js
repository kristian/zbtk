import { Buffer } from 'node:buffer';
import { reverseEndian } from './utils.js';

/**
 * As per ZigBee specification [1] the install codes are represented
 * as hexadecimals tuples of 4, separated by spaces, e.g.:
 *
 * 83FE D340 7A93 9723 A5C6 39B2 6916 D505 C3B5
 *
 * [1] ZigBee Device Behavior Specification, 10.1.1 Install Code format
 *
 * @param {Buffer} ic the Install Code (ic) to format
 * @param {boolean} [reverse] whether to reverse the endianess, e.g. when reading from a ZigBee packet to display
 * @returns {string} the formatted Install Code
 */
export function ic(ic, reverse) {
  return Array.from(reverse ? reverseEndian(ic) : ic)
    .map(byte => byte.toString(16).padStart(2, '0').toUpperCase())
    .reduce((result, byte, index) => result + byte +
      ((index % 2 === 1 && index !== ic.length - 1) ? ' ' : ''), '');
}

/**
 * As per IEEE specification the EUI(64)s are represented as hexadecimals
 * tuples of 2, separated by colons or dashes, e.g.:
 *
 * 00:0D:6F:00:00:00:00:01 or 00-0D-6F-00-00-00-00-01
 *
 * @param {Buffer} eui the EUI(64) to format
 * @param {string} [sep=':'] the separator to use
 * @param {boolean} [reverse] whether to reverse the endianess, e.g. when reading from a ZigBee packet to display
 * @returns {string} the formatted EUI(64)
 */
export function eui(eui, sep = (process.env.ZBTK_FORMAT_EUI_SEPARATOR || ':').toString()[0], reverse) {
  if (typeof sep === 'boolean') {
    reverse = sep;
    sep = euiSep;
  }

  return Array.from(reverse ? reverseEndian(eui) : eui)
    .map(byte => byte.toString(16).padStart(2, '0').toUpperCase())
    .reduce((result, byte, index) => result + byte +
      ((index !== eui.length - 1) ? sep : ''), '');
}

import { moduleHandler, dataMiddleware } from './utils.js';
export const command = {
  command: 'format <type> [data]',
  desc: 'Format ICs / EUIs / ...',
  builder: yargs => dataMiddleware(yargs
    .positional('type', {
      desc: 'Type',
      type: 'string',
      choices: ['ic', 'eui']
    }), { desc: 'Data to format' })
    .example('$0 format ic 83fed3407a939723a5c639b26916d505c3b5', 'Format the given data as an Install Code')
    .example('$0 format eui 01000000006f0d00', 'Format the given data as an EUI')
    .version(false)
    .help(),
  handler: moduleHandler(import.meta.url, 'type', 'data')
};

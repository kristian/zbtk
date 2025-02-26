import fs from 'fs/promises';
import traverse from 'traverse';
import { Buffer } from 'node:buffer';

/**
 * Get the value of an environment variable or a default value.
 *
 * @param {string} name of the environment variable
 * @param {string} [defaultValue=undefined] the default value to use
 * @returns {string} the value of the environment variable or the default value
 */
export function getEnvVar(name, defaultValue = undefined) {
  return name in process.env ? (process.env[name] || '') : defaultValue;
}

/**
 * Reverse the endian of a given buffer.
 *
 * Most values in the ZigBee protocol are little-endian encoded. For
 * display purpose however, values are mostly represented as big-endian.
 *
 * @param {Buffer} data the data to reverse the endian for
 * @returns {Buffer} the data with the endian reversed
 */
export function reverseEndian(data) {
  var temp = Buffer.allocUnsafe(data.length);
  for (var i = 0, j = data.length - 1; i <= j; ++i, --j) {
    temp[i] = data[j];
    temp[j] = data[i];
  }

  return temp;
}

const hexPrefix = getEnvVar('ZBTK_UTILS_HEX_PREFIX', '0x') || '';

/**
 * Convert the given hex string to a Buffer.
 *
 * @param {(string|Buffer)} data hex string to convert
 * @returns {Buffer} the data as a Buffer
 */
export function fromHex(data) {
  if (typeof data === 'string') {
    if (hexPrefix && data.startsWith(hexPrefix)) {
      data = data.slice(hexPrefix.length);
    }

    return Buffer.from(data.replaceAll(/[^0-9A-F]/gi, ''), 'hex');
  }

  return data;
}

/**
 * Represent binary data as hex in reverse-endian encoding, e.g.:
 * Buffer.from('a201', 'hex') gets represented as 0x01A2.
 *
 * @param {Buffer} data the data to represent as a hex value
 * @param {string} [prefix='0x'] the prefix to use for the hex value
 * @param {number} [pad=0] the number of bytes to pad the hex value with
 * @param {boolean} [reverse] whether to reverse the endianess, e.g. when reading from a ZigBee packet to display
 * @returns {string} the hex representation of the data
 */
export function toHex(data, prefix = hexPrefix, pad = 0, reverse) {
  if (typeof prefix === 'boolean') {
    reverse = prefix;
    prefix = hexPrefix;
  }
  if (typeof pad === 'boolean') {
    reverse = pad;
    pad = 0;
  }

  return `${prefix}${(reverse ? reverseEndian(data) : data).toString('hex').padStart(pad, '0').toUpperCase()}`;
}

/**
 * Parse JSON string that contains Buffers as $hex objects
 *
 * @param {string} text the JSON string to parse
 * @returns {object} the parsed JSON object
 */
export function jsonParse(text) {
  return traverse.forEach(JSON.parse(text), function(value) {
    if (typeof value === 'object' && value['$hex']) {
      this.update(Buffer.from(value['$hex'], 'hex'));
    }
  });
}

/**
 * Stringify object to JSON string, with Buffers as $hex objects
 *
 * @param {object} object the object to stringify
 * @param {boolean} [inline=false] whether to stringify inline or not, meaning to keep the buffers in the original object
 * @returns {string} the JSON string
 */
export function jsonStringify(object, inline = false) {
  // to prevent creating a deep copy to stringify, traverse the object twice instead

  // convert buffer to $hex objects
  traverse.forEach(object, function(value) {
    if (Buffer.isBuffer(value)) {
      const hex = { '$hex': value.toString('hex') };
      this.update(inline ? hex : Object.defineProperties(hex, {
        buffer: { value } // create a non-enumerable property, that is not taken into account by JSON.stringify
      }));
    }
  });

  const string = JSON.stringify(object);
  if (inline) {
    return string;
  }

  // revert the $hex objects to buffer
  traverse.forEach(object, function(value) {
    if (typeof value === 'object' && value['$hex']) {
      this.update(value.buffer);
    }
  });

  return string;
}

/**
 * Create a yargs handler for a module that exports a function
 *
 * @param {string} module the module to import
 * @param {string|function} [name=() => 'default'] the name of the function to import
 * @param {string|Array} [args='data'] the arguments to pass to the function
 * @param {function} [format=(out, argv) => out.toString()] the format function to use
 * @returns {function} the handler function
 */
export function moduleHandler(module, name = () => 'default', args = 'data', format = (out, argv) => {
  if (Buffer.isBuffer(out)) {
    return out.toString('hex');
  } else if (typeof out === 'object') {
    return jsonStringify(out);
  }

  return out.toString();
}) {
  return async argv => {
    console.log(format((await import(module))[typeof name === 'string' ? (argv[name] || 'default') : name(argv)]
      .apply(null, typeof args === 'string' ? [argv[args]] : args(argv)), argv));
  };
}

/**
 * Create a yargs middleware for handling input also from stdin
 *
 * @param {object} yargs the yargs object to extend
 * @param {string} [key='data'] the key to use for the data
 * @param {object} [options={ optional: false }] the options to use
 * @param {function} [convert=fromHex] the conversion function to use
 * @returns {object} the yargs object for chaining
 */
export function stdinMiddleware(yargs, key = 'data', options = { optional: false }, convert = fromHex) {
  if (typeof key !== 'string') {
    convert = options;
    options = key;
    key = 'data';
  }
  if (typeof options === 'function') {
    convert = options;
    options = { optional: false };
  }
  if (convert !== 'function') {
    convert = fromHex;
  }

  return yargs
    .positional(key, Object.assign({}, options, {
      type: 'string'
    }))
    .middleware(async argv => {
      if (argv.help) {
        return;
      }

      // note that stdin.isTTY is true in case there is NO input
      // and falsy (undefined) if there is data piped to stdin
      // see https://nodejs.org/api/tty.html#tty_tty
      if (!argv[key] && !process.stdin.isTTY && process.stdin.readable) {
        argv[key] = await new Promise(resolve => {
          setTimeout(resolve, 500); // fallback if no data becomes readable
          process.stdin.once('readable', () => {
            resolve(process.stdin.read()?.toString('utf8'));
          });
        });
      }

      if (argv[key]) {
        if (typeof convert === 'function') {
          argv[key] = convert(argv[key]);
        }

        for (const alias of ((typeof options?.alias === 'string' ? [options.alias] : options?.alias) || [])) {
          argv[alias] = argv[key];
        }
      }
    }, true)
    .check((argv, options) => {
      if (argv.help) {
        return true;
      } else if (!argv[key] && !options?.optional) {
        throw new TypeError(`Missing positional argument [${key}] nor anything was piped to stdin`);
      }

      return true;
    });
}

/**
 * Calls the CLI and returns the console output as string.
 *
 * @param {(string|string[])} args arguments to pass to the CLI
 * @param {number} [columns = 120] the number of columns to wrap the output at
 * @returns {Promise<string>} the output of the CLI
 */
export async function getCliOutput(args, columns = 100) {
  // dynamically import the CLI here, in order to not result in the utils.js module loading all tools by default
  const cli = (await import('./cli.js')).default;

  // set a fix width for getting the CLI output (especially to have the same results in the test runners)
  if (columns) {
    cli.wrap(columns);
  }

  try {
    let resolveOutput;
    const outputPromise = new Promise(resolve => resolveOutput = resolve);
    await cli.parseAsync(args, (err, argv, output) => {
      resolveOutput(output);
    });

    return await outputPromise;
  } finally {
    // reset the CLI width to yargs defaults
    cli.wrap(Math.min(80, cli.terminalWidth()));
  }
}

// internal utility CLI, e.g. to update README.md
import esMain from 'es-main';
if (esMain(import.meta)) {
  (await import('yargs')).default((await import('yargs/helpers')).hideBin(process.argv))
    .command('readme', 'Update README.md', async argv => {
      let readme = await fs.readFile('README.md', 'utf-8');

      // update table of contents (TOC)
      console.log('Updating table of contents in README.md');
      readme = readme.replace(/(?<=<!-- toctools -->)[\s\S]*(?=<!-- toctoolsend -->)/,
        Array.from(readme.matchAll(/### <a id='(.*)'><\/a>\[`(.*)`\]\(.*\) (.*)/g))
          .map(match => `\n  * [\`${match[2]}\` ${match[3]}](#${match[1]})`).join('')
      );

      // grab command help outputs from CLI
      const commands = {};
      for (const match of readme.matchAll(/```bash\nzbtk ([^<\[\n]*) ?/g)) {
        const command = match[1];
        if (commands[command]) {
          continue;
        }

        commands[command] = await getCliOutput(`${command} --help`);
      }

      // update CLI examples in README.md
      console.log('Updating CLI examples in README.md');
      await fs.writeFile('README.md', readme.replaceAll(
        /(?<=```bash\n)zbtk ([^<\[\n]*) ?[\s\S]*?(?=\n```)/g,
        // only replace CLIs that contain --help!
        (match, command) => match.includes('--help') ? commands[command] : match), 'utf-8');
    })
    .demandCommand()
    .help()
    .version(false)
    .parse();
}

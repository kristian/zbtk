#!/usr/bin/env node

import yargsFactory from 'yargs';
import { hideBin } from 'yargs/helpers';
import { commands } from './tools.js';
import packageJson from './package.json' with { type: 'json' };

const yargs = yargsFactory(hideBin(process.argv));
const cli = yargs
  .scriptName('zbtk')
  // rename command to tool
  .updateStrings({
    'command': 'tool',
    'Commands:': 'Tools:'
  })
  .command(commands)
  .demandCommand()
  .wrap(Math.min(120, yargs.terminalWidth()))
  .version(packageJson.version)
  .help();
export default cli;

import esMain from 'es-main';
if (esMain(import.meta)) {
  await cli.parseAsync();
}

#!/usr/bin/env node

import yargsFactory from 'yargs';
import { hideBin } from 'yargs/helpers';
import { commands } from './tools.js';

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
  .help()
  .version();
export default cli;

import esMain from 'es-main';
if (esMain(import.meta)) {
  await cli.parseAsync();
}

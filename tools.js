import * as cap from './cap.js';
import * as cluster from './cluster.js';
import * as crypto from './crypto.js';
import * as format from './format.js';
import * as hash from './hash.js';
import * as ic from './ic.js';
import * as parse from './parse.js';
import * as type from './type.js';

const tools = { cap, cluster, crypto, format, hash, ic, parse, type };
export default tools;

export const commands = Object.values(tools)
  .map(tool => [tool.command].concat(tool.commands || []))
  .flat().filter(command => command);

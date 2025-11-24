import test from 'ava';

import fs from 'node:fs';
import { env } from 'node:process';
import { join, basename, dirname } from 'node:path';

import { globSync as glob } from 'glob';
import { jsonParse, getCliOutput } from './utils.js';

import { default as tools, commands } from './tools.js';

// set pre-shared key(s) used in tests for decryption
tools.crypto.pk(Buffer.from('52f0fe8052ebb35907daa243c95a2ff4', 'hex')); // transport key 1
tools.crypto.pk(Buffer.from('75d76b7488a97eca4de4a363fabd9377', 'hex')); // transport key 2
tools.crypto.pk(Buffer.from('4c23a848a76f432113510a301c5fdfd2', 'hex')); // link key for install code EE91 7C25 E941 23C2 27B9 3F4D 50A0 C34F 373D

env.ZBTK_PARSE_FAIL_DECRYPT = '1';

/*
 Tests for cluster tool
*/

const getCluster = tools.cluster.default;
test('Cluster tool', t => {
  const cluster = getCluster(0x0001);
  t.is(cluster.id, 0x0001);
  t.is(cluster.name, 'Power Configuration');
  t.is(cluster.get(0x0000), 'Mains Voltage');
  t.is(cluster.get(0x4000), 'Manufacturer Specific');
  t.is(cluster.get(0x1000), undefined);

  // test generic clusters
  t.is(getCluster(0x7FAA).name, 'ZigBee Standard');
  t.is(getCluster(0xAAFF).name, 'Reserved');
  t.is(getCluster(0xFFAA).name, 'Manufacturer Specific');
});

/*
 Tests for parse tool
*/

// tests for parsing, compare stored packet data in test/parse/*/*.hex with expected test/parse/*/*.json results
for (const hexFile of glob('test/parse/*/*.hex')) {
  const name = basename(hexFile, '.hex'), parseType = basename(dirname(hexFile));
  const data = Buffer.from(fs.readFileSync(`${hexFile}`, 'utf-8'), 'hex');
  const expected = jsonParse(fs.readFileSync(`${join(dirname(hexFile), name)}.json`, 'utf-8'));
  const type = expected.$type || name.toUpperCase().replaceAll(/\d+$/g, '');
  delete expected.$type;

  test(`Parse ${name}`, t => {
    const packet = tools.parse.default(data, parseType);
    t.deepEqual(packet, expected);
    t.is(tools.type.default(packet, parseType), type);
  });
}

/*
 Tests for package.json
*/

const packageJson = JSON.parse(fs.readFileSync('package.json', 'utf-8'));

for (const name of Object.keys(tools)) {
  test(`${name} tool exported in package.json`, t => {
    t.assert(packageJson.exports[`./${name}`], `./${name}.js`);
  });
}

/*
 Tests for README.md
*/

const readme = fs.readFileSync('README.md', 'utf-8');

// test that all tools are mentioned in the README.md
for (const name of Object.keys(tools)) {
  test(`${name} tool in README.md`, t => {
    (readme.includes(`- [\`${name}.js\`](#zbtk-${name}): `) ||
      t.fail(`${name} tool bullet-point is missing / outdated in README.md`));
    (readme.includes(`### <a id='zbtk-${name}'></a>[\`${name}.js\`](${name}.js) `) ||
      t.fail(`${name} tool header is missing / outdated in README.md`));
    t.pass();
  });
}

// test that all tool CLIs are documented & current
['', ...commands.map(module => module.command.split(' ', 2)[0])].forEach(command => {
  // running yargs in parallel with async. middleware creates a dangling promise
  test.serial(`${command} tool CLI help in README.md`, async t => {
    const output = await getCliOutput(`${command} --help`);
    readme.includes(`\`\`\`bash\n${output}\n\`\`\``) ? t.pass() : t.fail(
      `${command} tool CLI help is missing / outdated in README.md`);
  });
});

// make sure that all JavaScript examples in README.md are available in /examples
const examples = Object.fromEntries(glob('examples/*.js').map(file => [basename(file), fs.readFileSync(file, 'utf8').trim()]));
for (const match of readme.matchAll(/(?<=```(?:js|javascript)\s*\n)[\s\S]*?(?=\n\s*```)/g)) {
  const js = match[0].replaceAll(/(?<=import .*? from ')zbtk\/([^']*)/g, '../$1.js');

  // check if the example is available in /examples
  test(`Example '${js.substring(0, 30)}...' in /examples`, t => {
    const exists = Object.values(examples).some(fileJs => fileJs.includes(js));
    !exists && console.log(js);
    exists ? t.pass() : t.fail();
  });
}

// make sure all examples in examples/ run without errors
for (const file of Object.keys(examples)) {
  test(`Example ${file} works`, async t => {
    try {
      await import(`./examples/${file}`);
    } catch (err) {
      // expect ECONNREFUSED for cap.js example
      if (err?.code !== 'ECONNREFUSED') {
        throw err;
      }
    }

    t.pass();
  });
}

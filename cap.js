import pcapParser from 'pcap-parser';
import capDecoders from 'cap-decoders';
const capProtocols = capDecoders.PROTOCOL;

import { Buffer } from 'node:buffer';
import { env, stdin } from 'node:process';
import { Readable as ReadableStream } from 'node:stream';

import { EventEmitter } from 'node:events';
import { connectAsync as mqttConnect } from 'mqtt';

import { pk } from './crypto.js';
import { parse as parsePacket, parseZep } from './parse.js';
import { eui as rawFormatEui } from './format.js';
function formatEui(data) {
  // all EUIs that we format here are read LE from the packet, so reverse before display
  return rawFormatEui(data, /* reverse = */true);
}
import getPacketType from './type.js';
import getCluster from './cluster.js';
import { toHex as rawToHex, fromHex, jsonStringify, reverseEndian } from './utils.js';
function toHex(data) {
  // all hex that we format here is read LE from the packet, so reverse before display
  return rawToHex(data, /* reverse = */true);
}

import whence from 'whence';

function id(address) {
  return fromHex(address).toString('hex');
}

const addressTable = {};
function populateAddressTable(eui, addr) {
  if (!Buffer.isBuffer(addr = fromHex(addr)) || addr.length !== 2) {
    throw new TypeError(`Invalid 16-bit network address ${toHex(addr)} for device ${formatEui(eui)}`);
  }
  const addrNo = addr.readUInt16LE(0);
  if (addrNo >= 0xFFF8) {
    throw new RangeError(`Cannot add reserved broadcast 16-bit network address ${toHex(addr)} to address table`);
  }
  const addrId = id(addr);
  if (addressTable[addrId] && !addressTable[addrId].equals(eui)) {
    throw new Error(`Conflict in address table! Both ${formatEui(addressTable[addrId])} and ${formatEui(eui)} use 16-bit network address ${toHex(addr)}`);
  }

  addressTable[addrId] = Buffer.from(eui);
}

function capDecoderUnwrapFunction(capDecoder, checkNextLayerInfo) {
  return (data, nextLayer, logger) => {
    const decode = capDecoders[capDecoder](data);

    if (checkNextLayerInfo && typeof nextLayer === 'string') {
      const checkValue = checkNextLayerInfo.layers[nextLayer];
      if (checkValue !== undefined && decode.info[checkNextLayerInfo.field] !== checkValue) {
        logger.warn(`Received unexpected packet layer, expected '${nextLayer}' (with ${checkNextLayerInfo.field}: ${checkValue}), got ${decode.info[checkNextLayerInfo.field]}`);
        return;
      }
    }

    return data.subarray(decode.offset, decode.info.length ?
      decode.offset + decode.info.length : undefined);
  };
}
const unwrapFunctions = { // functions with interface (data: Buffer, nextLayer: string, logger) => Buffer
  'eth': capDecoderUnwrapFunction('Ethernet', {
    field: 'type',
    layers: {
      'ip4': capProtocols.ETHERNET.IPV4,
      'ip6': capProtocols.ETHERNET.IPV6
    }
  }),
  'ip4': capDecoderUnwrapFunction('IPV4', {
    field: 'protocol',
    layers: {
      'tcp': capProtocols.IP.TCP,
      'udp': capProtocols.IP.UDP
    }
  }),
  'ip6': capDecoderUnwrapFunction('IPV6', {
    field: 'protocol',
    layers: {
      'tcp': capProtocols.IP.TCP,
      'udp': capProtocols.IP.UDP
    }
  }),
  'tcp': capDecoderUnwrapFunction('TCP', {
    field: 'dstport',
    layers: {
      'zep': 17754
    }
  }),
  'udp': capDecoderUnwrapFunction('UDP', {
    field: 'dstport',
    layers: {
      'zep': 17754
    }
  })
};

export default { process };

/**
 * Process a PCAP input stream or file path and emit events of 'data', 'packet' and 'attribute' (and 'error') via the returned `EventEmitter`.
 *
 * @param {(string|ReadableStream)} [input=process.stdin] the input to read the PCAP data from, either a PCAP string or a `ReadableStream` (e.g. process.stdin)
 * @param {object} [options] the capture options
 * @param {(string|(data: Buffer, nextLayer: (string|(data: Buffer) => Buffer), logger: object) => Buffer|(string|(data: Buffer, nextLayer: (string|(data: Buffer) => Buffer), logger: object) => Buffer)[])} [options.unwrapLayers] the layers to unwrap to get to the WPAN package / layer, either one of 'eth', 'ip4', 'ip6', 'tcp', 'udp', 'zep', or a plain function transforming a `Buffer` or an array of those, in order of unwrapping to occur. Note that if the last layer is set to 'zep', the parser will automatically switch to parsing ZEP packets instead of WPAN packets. Also filters, logs and emitted packets will be based on the ZEP instead of the WPAN layer.
 * @param {(string|string[])} [options.emit=['attribute']] the events to emit via the returned EventEmitter and MQTT in case MQTT options are supplied, either one of 'data', 'packet' (WPAN) and/or 'attribute', 'error' events always getting emitted from the returned EventEmitter regardless of the settings
 * @param {string|object|(context: object) => Promise<boolean>} [options.filter] the filter to apply to the packets, a eval-estree-expression expression (see https://github.com/jonschlinkert/eval-estree-expression?tab=readme-ov-file#examples), estree-compatible expression AST, or filter function
 * @param {object} [options.out] the output options
 * @param {(boolean|string|string[])} [options.out.log] the events to log, any 'data', 'packet' (WPAN) and / or 'attribute', additionally 'verbose', 'info', 'warn', 'error' or 'silent' sets the log-level, default is 'info'. true to log all emitted events as well as enable 'info' logging, false to disable logging entirely
 * @param {object} [options.out.mqtt] the MQTT output options
 * @param {string} [options.out.mqtt.url] the MQTT broker URL
 * @param {object} [options.out.mqtt.options] the MQTT connection options
 * @param {object} [options.out.mqtt.client] the MQTT client instead of creating a new one. attention: calling close() will *not* close this client
 * @param {string} [options.out.mqtt.topic='zbtk'] the MQTT topic to publish the packets to
 * @param {(buffer: Buffer) => any} [options.bufferFormat] a function to format buffers before emitting them to console / MQTT
 * @returns {Promise<EventEmitter>} a promise to an event emitter (with an additional close method), emitting events of 'options.emit' and 'error' events
 */
export async function process(input = stdin, options) {
  if (input instanceof ReadableStream) {
    input.pause();
  } else if (!input || typeof input === 'object') {
    options = input || options;
    input = stdin;
  }

  let mqttClient, mqttTopic;
  const mqtt = options?.out?.mqtt;
  if (mqtt) {
    mqttClient = mqtt.client || await mqttConnect(
      mqtt.url, mqtt.options);
    mqttTopic = mqtt.topic || 'zbtk';
  }

  let emit = options?.emit;
  if (emit === undefined) {
    emit = ['attribute'];
  } else if (typeof emit === 'string') {
    emit = [emit];
  }
  if (!Array.isArray(emit) || (emit = emit.filter(name => ['data', 'packet', 'attribute'].includes(name))).length === 0) {
    throw new TypeError('No valid events to emit, must be one or multiple of "data", "packet" or "attribute"');
  }

  let log = options?.out?.log;
  if (typeof log === 'boolean') {
    log = log ? [...emit, 'info'] : [];
  } else if (!log) {
    log = ['info'];
  } else if (typeof log === 'string') {
    log = [log];
  } else if (!Array.isArray(log)) {
    throw new TypeError('Invalid log option, must be a boolean, string or array of strings');
  }

  emit = new Set(emit);
  log = new Set(log);
  let logLevel = 0; // no logging
  let logPksInfo = true;
  if (log.size) {
    log.delete('error') && (logLevel = 1);
    log.delete('warn') && (logLevel = 2);
    log.delete('info') && (logLevel = 3);
    log.delete('verbose') && (logLevel = 4);
    logLevel = log.delete('silent') ? 0 : (logLevel || 3); // default to info if no other log level is set
  }
  const events = new Set([...emit, ...log]); // union
  events.delete('error');

  let filter;
  if (typeof options?.filter === 'function') {
    filter = options.filter;
  } else if (options?.filter) {
    filter = whence.compile(options.filter);
  }

  let parseType = 'wpan', // by default parse IEEE 802.15.4 Low-Rate Wireless PAN (WPAN) packets, special case the last unwrap layer is 'zep'
    unwrap = (data, logger) => data; // by default a no-op, but if unwrapLayers are defined, a pre-compiled list of unwrap functions;
  const unwrapLayers = (options?.unwrapLayers && (Array.isArray(options.unwrapLayers) ? options.unwrapLayers : [options.unwrapLayers])) || [];
  if (unwrapLayers.length && unwrapLayers[unwrapLayers.length - 1] === 'zep') {
    parseType = 'zep'; // set the parser to parse ZigBee Encapsulation Protocol (ZEP) packets, to account for the last unwrap layer
    unwrapLayers.pop();
  }
  unwrapLayers.forEach((layer, index) => {
    let unwrapFunction = typeof layer === 'function' ? layer : unwrapFunctions[layer];
    if (typeof unwrapFunction !== 'function') {
      throw new TypeError(`Unknown unwrap layer specified at index ${index}: ${layer}`);
    }

    const previousUnwrap = unwrap;
    unwrap = (data, logger) => unwrapFunction(previousUnwrap(data, logger), unwrapLayers[index + 1], logger);
  });

  const eventEmitter = new EventEmitter();
  eventEmitter.on('error', function() {
    // nothing to do here, our EventEmitter should not crash in case no
    // handler is present. errors are still logged to console instead
  });
  eventEmitter.close = async function() {
    if (!mqtt?.client && mqttClient) {
      await mqttClient.end();
    }
  };

  const parser = pcapParser.parse(input);

  parser.on('packet', async function(rawPacket) {
    const context = {};
    const logger = { // define the logger in-line, to access the current context
      verbose: logLevel >= 4 ? console.trace : () => {},
      info: logLevel >= 3 ? console.log : () => {},
      warn: logLevel >= 2 ? console.warn : () => {},
      error: function(...params) {
        if (!Array.isArray(params)) {
          params = params ? [params] : [];
        }
        if (!params.length) {
          params = ['Unknown error occurred'];
        }

        let err = params.pop();
        if (!(err instanceof Error)) {
          if (!params.length) {
            err = new Error(err);
          } else {
            params.push(err);
            err = new Error(params[0]);
          }
        }

        eventEmitter.emit('error', err, context);
        if (logLevel >= 1) {
          console.error(...params, err);
        }
      }
    };

    let unwrapData;
    try {
      unwrapData = unwrap(rawPacket.data);
    } catch (err) {
      logger.error('Failed to unwrap packet!', rawPacket.data.toString('hex'), err);
      return; // no further processing of this packet
    }

    const data = context.data = unwrapData;

    let packet, packetStr, packetType, packetErr;
    // parse the packet only if a filter is defined or if we are going to emit / log the parsed packet or its attributes
    if (filter || (events.has('packet') || events.has('attribute'))) {
      try {
        packet = Object.defineProperty(parsePacket(data, parseType), 'toString', {
          value: function() {
            return packetStr || (packetStr = jsonStringify(this));
          }
        });
      } catch (err) {
        logger.error('Malformed packet!', data.toString('hex'), packetErr = err);
      }

      if (packet && !packetErr) {
        try {
          packetType = getPacketType(packet, parseType);
        } catch (err) {
          logger.error('Failed to determine packet type!', data.toString('hex'), err);
          // nothing to do here
        } finally {
          packetType ||= 'UNKNOWN';
        }
      } else {
        packetType = 'MALFORMED';
      }
    } else {
      packetType = 'NOT_PARSED';
    }

    const wpan = parseType === 'zep' ? packet?.wpan : packet;
    if (packetType === 'APS_CMD_TRANSPORT_KEY') {
      const key = wpan?.zbee_nwk?.zbee_aps?.cmd?.key;
      if (Buffer.isBuffer(key)) {
        const newPk = pk(key);

        logger.info();
        logger.info('-'.repeat(60));
        logger.info();
        logger.info(`Captured Transport Key ${key.toString('hex')}`);
        logger.info();
        logger.info(newPk ? 'Key was automatically added to pre-configured key list' : 'Key was already present in pre-configured key list');
        logger.info();
        logger.info('-'.repeat(60));
        logger.info();
      }
    }

    Object.assign(context, { packet, type: packetType });
    if (filter && !(await filter(context))) {
      return;
    }

    if (log.has('data')) {
      console.log(data.toString('hex'), `(${packetType})`);
    }
    if (emit.has('data')) {
      eventEmitter.emit('data', data, context);
      if (mqtt) {
        try {
          await mqttClient.publishAsync(mqttTopic, data);
        } catch (err) {
          logger.error('MQTT publish raw packet failed', err);
        }
      }
    }

    if (!packet || packetErr) {
      return;
    }

    if (log.has('packet')) {
      console.log(packet.toString() /* internally calls jsonStringify */, `(${packetType})`);
    }
    if (emit.has('packet')) {
      eventEmitter.emit('packet', packet, context);
      if (mqtt) {
        try {
          await mqttClient.publishAsync(mqttTopic, packet.toString() /* internally calls jsonStringify */);
        } catch (err) {
          logger.error('MQTT publish packet failed', err);
        }
      }
    }

    if (!events.has('attribute')) {
      return;
    }

    const zbee_nwk = wpan.zbee_nwk;
    if (!zbee_nwk) {
      return;
    }

    // populate address table, in case EUIs are to be published
    if (!env.ZBTK_CAP_PASS_NO_EUI) {
      try {
        if (zbee_nwk.fc.ext_src) {
          populateAddressTable(zbee_nwk.src64, zbee_nwk.src);
        }
        if (zbee_nwk.fc.ext_dst) {
          populateAddressTable(zbee_nwk.dst64, zbee_nwk.dst);
        }
        if (zbee_nwk.sec) {
          populateAddressTable(zbee_nwk.sec.src64, wpan.src16);
          if (zbee_nwk.fc.end_device_initiator) {
            populateAddressTable(zbee_nwk.sec.src64, zbee_nwk.src);
          }
        }
      } catch (err) {
        logger.error(err);
      }
    }

    if (zbee_nwk.sec && zbee_nwk.data) {
      logger.warn('Packet encrypted / decryption failed or not attempted');
      if (logPksInfo) {
        logger.info('Set or check ZBTK_CRYPTO_(WELL_KNOWN_)PKS environment variable(s) or capture Transport Key');
        logPksInfo = false; // only log the PKS info once
      }
    }

    if (!packetType.startsWith('ZCL_') || packetType.endsWith('_ACK') || !zbee_nwk.sec || !zbee_nwk.zbee_aps?.zbee_zcl) {
      return;
    }

    let addr, eui, write = false;
    if (packetType === 'ZCL_CMD_READ_ATTR_RSP' || packetType === 'ZCL_CMD_REPORT_ATTR') {
      addr = zbee_nwk.src;
      eui = zbee_nwk.fc.ext_src ? zbee_nwk.src64 : (zbee_nwk.fc.end_device_initiator ? zbee_nwk.sec.src64 : addressTable[id(addr)]);
    } else if (packetType === 'ZCL_CMD_WRITE_ATTR') {
      addr = zbee_nwk.dst;
      eui = zbee_nwk.fc.ext_dst ? zbee_nwk.dst64 : addressTable[id(addr)];
      write = true;
    } else {
      return;
    }

    // assign further context attributes after extraction from the packet in big-endian format
    Object.assign(context, eui && { eui: reverseEndian(eui) }, { addr: reverseEndian(addr), write });

    if (!env.ZBTK_CAP_PASS_NO_EUI && !eui) {
      logger.warn(`Devices ${toHex(addr)} 64-Bit Extended Unique Identifier (EUI-64) neither present in packet, nor in address table (yet)`);
      return;
    }

    const zbee_aps = zbee_nwk.zbee_aps;
    // we always expose big-endian to the consumer, little-endian is only for internal use / packet parsing
    Object.assign(context, { cluster: reverseEndian(zbee_aps.cluster), profile: reverseEndian(zbee_aps.profile) });

    for (const intAttr of zbee_aps.zbee_zcl.attrs) {
      const attr = { // same as for the context variables, expose big-endian instead of little-endian
          id: reverseEndian(intAttr.id),
          value: Buffer.isBuffer(intAttr.value) ? reverseEndian(intAttr.value) : intAttr.value
        }, outAttr = {
          id: rawToHex(attr.id),
          value: Buffer.isBuffer(intAttr.value) ? (typeof options?.bufferFormat === 'function' ?
              options.bufferFormat(attr.value) : rawToHex(attr.value)) : attr.value
        };

      if (log.has('attribute')) {
        const cluster = getCluster(context.cluster);
        console.log(`${cluster?.name || 'Unknown Cluster'} (${toHex(zbee_aps.cluster)})/${cluster?.get?.(attr.id) || 'Unknown Attribute'} (${outAttr.id}): ${Buffer.isBuffer(outAttr.value) ? rawToHex(outAttr.value) : outAttr.value} (${write ? 'written to' : 'read from'} ${!env.ZBTK_CAP_PASS_NO_EUI ? formatEui(eui) : toHex(addr)})`);
      }

      eventEmitter.emit('attribute', attr, context);
      if (mqtt) {
        try {
          await mqttClient.publishAsync(`${mqttTopic}/${!env.ZBTK_CAP_PASS_NO_EUI ? formatEui(eui) : toHex(addr)}/${toHex(zbee_aps.cluster)}/${outAttr.id}`,
            Buffer.isBuffer(outAttr.value) ? outAttr.value : `${outAttr.value}`);
        } catch (err) {
          logger.error(err, 'MQTT publish attribute failed');
        }
      }
    }
  });
  // when the parser (or underlying stream) ends, close the MQTT client if we created it and re-emit the end event to our EventEmitter
  parser.on('end', async function() {
    try {
      await eventEmitter.close();
    } finally {
      eventEmitter.emit('end');
    }
  });
  // re-emit error events to our EventEmitter
  parser.on('error', function(err) {
    eventEmitter.emit('error', err);
  });

  return eventEmitter;
}

export const command = {
  command: 'cap [file]',
  desc: 'Packet / Attribute (to MQTT) Capture',
  builder: yargs => yargs
    .positional('file', {
      desc: 'PCAP file to read instead of STDIN',
      type: 'string'
    })
    .option('unwrap', {
      alias: 'u',
      desc: 'Layers to unwrap to get to the WPAN packet',
      type: 'array',
      choices: ['eth', 'ip4', 'ip6', 'tcp', 'udp', 'zep']
    })
    .option('emit', {
      alias: 'e',
      desc: 'Events to emit to MQTT',
      type: 'array',
      choices: ['data', 'packet', 'attribute'],
      default: ['attribute']
    })
    .option('log', {
      alias: 'l',
      desc: 'Log outputs, defaults "info", if no output MQTT also to "packet", --no-log to disable',
      type: 'array',
      choices: [false, 'data', 'packet', 'attribute', 'verbose', 'info', 'warn', 'error', 'silent']
    })
    .option('filter', {
      alias: 'f',
      desc: 'Filter packets to emit / log (whence expression)',
      type: 'string'
    })
    .option('mqtt-host', {
      alias: 'mh',
      desc: 'MQTT broker host',
      type: 'string'
    })
    .option('mqtt-port', {
      alias: 'mp',
      desc: 'MQTT broker port',
      type: 'number',
      default: 1883
    })
    .option('mqtt-username', {
      alias: ['mu', 'mqtt-user'],
      desc: 'MQTT broker username',
      type: 'string'
    })
    .option('mqtt-password', {
      alias: ['mp', 'mqtt-pw', 'mqtt-pass'],
      desc: 'MQTT broker password',
      type: 'string'
    })
    .option('mqtt-topic', {
      alias: 'mt',
      desc: 'MQTT topic',
      type: 'string',
      default: 'zbtk'
    })
    .middleware(argv => {
      // allow comma-separated lists for unwrap
      argv.unwrap = (argv.unwrap || []).map(layer => layer ? layer?.split(',') : []).flat();
    }, /* applyBeforeValidation = */true)
    .check((argv, options) => {
      if (argv.help) {
        return true;
      } else if (!argv.file && stdin.isTTY) {
        // note that stdin.isTTY is true in case there is NO input
        // and falsy (undefined) if there is data piped to stdin
        // see https://nodejs.org/api/tty.html#tty_tty
        throw new TypeError(`Missing positional argument [file], or data piped into stdin`);
      }

      return true;
    })
    .middleware(async argv => {
      if (argv.help) {
        return;
      } else if (!argv.log) {
        argv.log = ['info'];
        if (!argv.mqttHost) {
          argv.log.push('packet');
        }
      } else if (argv.log.includes(false)) {
        argv.log = false;
      }
    })
    .example(`$0 cap trace.pcap --filter 'type != \\"WPAN_ACK\\" && type != \\"WPAN_COMMAND\\"'`, 'Process trace.pcap for non-WPAN packets and print them to console')
    .example('$0 cap --emit attribute --mqtt-host localhost --mqtt-user user --mqtt-pass password', 'Process packets from STDIN and emit captured attributes to an MQTT broker')
    .version(false)
    .help(),
  handler: async argv => {
    await process(argv.file, {
      unwrapLayers: argv.unwrap,
      emit: argv.emit,
      filter: argv.filter,
      out: {
        log: argv.log,
        mqtt: argv.mqttHost && {
          url: `mqtt://${argv.mqttHost}:${argv.mqttPort}`,
          options: {
            username: argv.mqttUsername,
            password: argv.mqttPassword
          },
          topic: argv.mqttTopic
        }
      }
    });
  }
};

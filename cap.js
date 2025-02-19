import capModule from 'cap';
const { Cap, decoders } = capModule;
const capProtocols = decoders.PROTOCOL;

import { EventEmitter } from 'node:events';
import { connectAsync as mqttConnect } from 'mqtt';

import { pk } from './crypto.js';
import { parse as parsePacket } from './parse.js';
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
  const addrId = id(addr);
  if (addressTable[addrId] && !addressTable[addrId].equals(eui)) {
    throw new Error(`Conflict in address table! Both ${formatEui(addressTable[addrId])} and ${formatEui(eui)} use use 16-bit network address ${toHex(addr)}`);
  }

  addressTable[addrId] = Buffer.from(eui);
}

export default { open };

/**
 * Open a capture device for packet capture and emit events of 'data', 'packet' and 'attribute' (and 'error') via the returned EventEmitter.
 *
 * @param {string} device the device to open for capture
 * @param {object} [options] the capture options
 * @param {(string|string[])} [options.emit=['attribute']] the events to emit via the returned EventEmitter and MQTT in case MQTT options are supplied, either one of 'data', 'packet' and/or 'attribute', 'error' events always getting emitted from the returned EventEmitter regardless of the settings
 * @param {string|object|function} [options.filter] the filter to apply to the packets, a eval-estree-expression expression (see https://github.com/jonschlinkert/eval-estree-expression?tab=readme-ov-file#examples), estree-compatible expression AST, or filter function
 * @param {object} [options.out] the output options
 * @param {(boolean|string|string[])} [options.out.log] the events to log, any 'data', 'packet' and / or 'attribute', additionally 'verbose', 'info', 'warn' or 'error' sets the log-level, default is 'info'. true to log all emitted events as well as enable 'info' logging, false to disable logging entirely
 * @param {object} [options.out.mqtt] the MQTT output options
 * @param {string} [options.out.mqtt.url] the MQTT broker URL
 * @param {object} [options.out.mqtt.options] the MQTT connection options
 * @param {object} [options.out.mqtt.client] the MQTT client instead of creating a new one. attention: calling close() will *not* close this client
 * @param {string} [options.out.mqtt.topic='zbtk'] the MQTT topic to publish the packets to
 * @param {number} [options.bufferSize=10485760] the buffer size to use for packet capture
 * @returns {Promise<EventEmitter>} a promise to an event emitter (with an additional close method), emitting events of 'options.emit' and 'error' events
 */
export async function open(device, options) {
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
    logLevel = logLevel || 3; // default to info if no other log level is set
  }
  const events = new Set([...emit, ...log]); // union
  events.delete('error');

  const bufferSize = options?.bufferSize || 10 * 1024 * 1024, buffer = Buffer.alloc(bufferSize);

  let filter;
  if (typeof options?.filter === 'function') {
    filter = options.filter;
  } else if (options?.filter) {
    filter = whence.compile(options.filter);
  }

  const cap = new Cap();
  cap.open(device, '', bufferSize, buffer);
  cap.setMinBytes && cap.setMinBytes(0);

  const eventEmitter = new EventEmitter();
  eventEmitter.on('error', function() {
    // nothing to do here, our EventEmitter should not crash in case no
    // handler is present. errors are still logged to console instead
  });
  eventEmitter.close = async function() {
    try {
      cap.close();
    } finally {
      // close the MQTT client in any case
      if (!mqtt.client && mqttClient) {
        await mqttClient.end();
      }
    }
  };

  cap.on('packet', async function() {
    const eth = decoders.Ethernet(buffer);
    if (eth.info.type !== capProtocols.ETHERNET.IPV4) {
      return;
    }

    const ip = decoders.IPV4(buffer, eth.offset);
    if (ip.info.protocol !== capProtocols.IP.UDP) {
      return;
    }

    const udp = decoders.UDP(buffer, ip.offset);
    if (udp.info.dstport !== 17754) { // Encap. ZigBee Packets
      return;
    }

    const data = buffer.subarray(udp.offset, udp.offset + udp.info.length);

    const context = { data };
    const logger = {
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

    let packet, packetStr, packetType, packetErr;
    // parse the packet only if a filter is defined or if we are going to emit / log the parsed packet or its attributes
    if (filter || (events.has('packet') || events.has('attribute'))) {
      try {
        packet = Object.defineProperty(parsePacket(data), 'toString', {
          value: function() {
            return packetStr || (packetStr = jsonStringify(this));
          }
        });
      } catch (err) {
        logger.error('Malformed packet!', data.toString('hex'), packetErr = err);
      }

      if (packet && !packetErr) {
        try {
          packetType = getPacketType(packet);
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

    if (packetType === 'APS_CMD_TRANSPORT_KEY') {
      const key = packet?.wpan?.zbee_nwk?.zbee_aps?.cmd?.key;
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

    Object.assign(context, { data, packet, type: packetType });
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

    const wpan = packet.wpan, zbee_nwk = wpan.zbee_nwk;
    if (!zbee_nwk) {
      return;
    }

    // populate address table, in case EUIs are to be published
    if (!process.env.ZBTK_CAP_PASS_NO_EUI) {
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

    if (!process.env.ZBTK_CAP_PASS_NO_EUI && !eui) {
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
        }, hexAttr = {
          id: toHex(intAttr.id),
          value: Buffer.isBuffer(intAttr.value) ? toHex(intAttr.value) : intAttr.value
        };

      if (log.has('attribute')) {
        const cluster = getCluster(context.cluster);
        console.log(`${cluster?.name || 'Unknown Cluster'} (${toHex(zbee_aps.cluster)})/${cluster?.get?.(attr.id) || 'Unknown Attribute'} (${hexAttr.id}): ${hexAttr.value} (${write ? 'written to' : 'read from'} ${!process.env.ZBTK_CAP_PASS_NO_EUI ? formatEui(eui) : toHex(addr)})`);
      }

      eventEmitter.emit('attribute', attr, context);
      if (mqtt) {
        try {
          await mqttClient.publishAsync(`${mqttTopic}/${!process.env.ZBTK_CAP_PASS_NO_EUI ? formatEui(eui) : toHex(addr)}/${toHex(zbee_aps.cluster)}/${hexAttr.id}`,
            Buffer.isBuffer(attr.value) ? attr.value : `${attr.value}`);
        } catch (err) {
          logger.error(err, 'MQTT publish attribute failed');
        }
      }
    }
  });

  return eventEmitter;
}

export const command = {
  command: 'cap [device]',
  desc: 'Packet / Attribute (to MQTT) Capture',
  builder: yargs => yargs
    .positional('device', {
      desc: 'Capture device to use',
      type: 'string',
      conflicts: 'list-devices'
    })
    .option('list-devices', {
      alias: ['list'],
      desc: 'List all available capture devices',
      type: 'boolean',
      conflicts: 'device'
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
      choices: [false, 'data', 'packet', 'attribute', 'info', 'warn', 'error', 'verbose']
    })
    .option('filter', {
      alias: 'f',
      desc: 'Filter packets to emit / log (whence expression)',
      type: 'string'
    })
    .option('mqtt-host', {
      alias: 'h',
      desc: 'MQTT broker host',
      type: 'string'
    })
    .option('mqtt-port', {
      alias: 'p',
      desc: 'MQTT broker port',
      type: 'number',
      default: 1883
    })
    .option('mqtt-username', {
      alias: ['u', 'user', 'mqtt-user'],
      desc: 'MQTT broker username',
      type: 'string'
    })
    .option('mqtt-password', {
      alias: ['pw', 'pass', 'mqtt-pw', 'mqtt-pass'],
      desc: 'MQTT broker password',
      type: 'string'
    })
    .option('mqtt-topic', {
      alias: 't',
      desc: 'MQTT topic',
      type: 'string',
      default: 'zbtk'
    })
    .check((argv, options) => {
      if (argv.help) {
        return true;
      } else if (!argv.listDevices && !argv.device) {
        throw new TypeError('Either specify a <device> to capture or use --list-devices to list all available capture devices');
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
    .example('$0 cap --list-devices', 'List all available capture devices')
    .example(`$0 cap '\\Device\\NPF_{83B280A6-6C08-4F7A-A8F2-9C88E12998CD}' --filter 'type != \\"WPAN_ACK\\" && type != \\"WPAN_COMMAND\\"'`, 'Capture non-WPAN packets and print them to console')
    .example('$0 cap /dev/en0 --emit attribute --mqtt-host localhost --mqtt-user user --mqtt-password password', 'Capture packets from /dev/en0 and emit captured attributes to an MQTT broker')
    .version(false)
    .help(),
  handler: async argv => {
    if (argv.listDevices) {
      const devices = Cap.deviceList();
      if (devices.length === 0) {
        console.log('No capture devices found');
      } else {
        devices.forEach(device => console.log(`Cap. Device: ${device.name}\nDescription: ${device.description}\n`));
      }
    } else {
      await open(argv.device, {
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
  }
};

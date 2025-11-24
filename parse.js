import { env } from 'node:process';
import { Buffer } from 'node:buffer';
import { Parser } from 'binary-parser-encoder-bump';
import { pks, decrypt } from './crypto.js';
import { crc, key as hashKey } from './hash.js';

import traverse from 'traverse';

const formatters = {
  bool: value => !!value,
  datetime: buffer => buffer, // TODO
  hoist: function(object) {
    if (object.$hoist) {
      Object.assign(this, object.$hoist);
      return this;
    }

    return object;
  }
};

function optional(name, options) {
  if (!options) {
    options = name;
    name = undefined;
  }

  return {
    tag: function() {
      return (typeof options.tag === 'string' ?
        this[options.tag] : options.tag.apply(this)) ? 1 : 0;
    },
    formatter: options.formatter,
    defaultChoice: options.default || new Parser(), // empty parser / don't include anything
    choices: {
      1: name ? new Parser().nest(name, {
        type: options.type
      }) : options.type
    }
  };
}

function assertFunction(text, fn) {
  const textFunction = function() {
    return fn.apply(this, arguments);
  };
  textFunction.toString = function() {
    return typeof text === 'function' ? text.apply(this, arguments) : text;
  };
  return textFunction;
}

function parent(context, field) {
  while (context) {
    if (field in context) {
      return context[field];
    } else {
      context = context.$parent;
    }
  }

  return undefined;
}

function generateSecureParser(name, aadLength, choices, defaultChoice = () => null) {
  const tempContext = {}; // TODO remove as soon as https://github.com/keichi/binary-parser/issues/263 is fixed
  return new Parser()
    .namely(name)
    .useContextVars()
    .nest('sec', {
      type: new Parser()
        .buffer('scf', { length: 1 }) // le
        .seek(-1)
        .nest('sc', {
          type: new Parser()
            .bit1('$unused')
            .bit1('verified_fc')
            .bit1('ext_nonce', { formatter: formatters.bool })
            .bit2('key_id')
            .bit3('sec_level')
        })
        .uint32le('counter')
        .buffer('src64', { length: 8 }) // le
        .choice(optional({
          tag: function() { return this.sc.key_id === 0x1; }, // Network Key
          type: new Parser()
            .uint8('key_seqno')
        }))
        .pointer('mic', {
          offset: function() {
            return parent(this, '$wpanStart') + parent(this, '$wpanLength') - 6; // 2 bytes TI CC24xx-format metadata, 4 bytes mic
          },
          type: new Parser()
            .buffer('data', { length: 4 }),
          formatter: parser => parser.data // do not nest pointer
        })
    })
    .saveOffset('$dataOffset')
    .buffer('$data', {
      length: function() {
        return parent(this, '$wpanLength') - (this.$dataOffset - parent(this, '$wpanStart')) - 6; // 2 bytes TI CC24xx-format metadata, 4 bytes mic;
      }
    })
    .choice(optional({
      tag: () => pks.length, // if there are any pre-shared keys, try to decrypt the payload with it
      default: new Parser().buffer('data', { // keep the raw data
        readUntil: () => true, // do not read any additional data
        formatter: function() {
          return this.$data;
        }
      }),
      type: new Parser()
        .pointer('$aad', {
          offset: function() {
            return parent(this, '$zbee_aadStart');
          },
          type: new Parser().buffer('data', {
            length: aadLength
          }),
          formatter: parser => parser.data // do not nest pointer
        })
        .buffer('$decrypt', { // override the data field with the decrypted data
          readUntil: () => true, // do not read any additional data
          formatter: function() {
            // try to decrypt with any one of the pre-shared keys
            let lastErr;
            for (let k of pks) {
              if (this.sec.sc.key_id === 0x2) { // key-transport key
                k = hashKey(k, 0x00);
              } else if (this.sec.sc.key_id === 0x3) { // key-load key
                k = hashKey(k, 0x02);
              }

              try {
                return decrypt(this.$data, k, this.sec.src64, this.sec.counter, this.sec.scf, this.$aad, this.sec.mic);
              } catch (err) {
                lastErr = err;
              }
            }

            if (env.ZBTK_PARSE_FAIL_DECRYPT) {
              throw lastErr;
            } else {
              return 'DECRYPT_FAIL'; // in case decryption fails, keep the raw data
            }
          }
        })
        .choice({
          tag: function() {
            const decrypt = this.$decrypt;
            if (!Buffer.isBuffer(decrypt)) {
              // decryption failed, keep original data only
              return 0xF;
            } else {
              // keep decrypted data only
              tempContext.data = this.$data = decrypt;

              return parent(this, 'fc').type;
            }
          },
          defaultChoice: defaultChoice(tempContext), // TODO no longer needed as a function, as soon as tempContext can be removed
          choices: {
            ...(choices(tempContext)), // TODO no longer needed as a function, as soon as tempContext can be removed

            0xF: new Parser().buffer('data', { // keep the raw data
              readUntil: () => true, // do not read any additional data
              formatter: function() {
                return this.$data;
              }
            })
          }
        })
    }));
}

function zclAttrValueChoice(typeTag = 'type[0]', complex = true) {
  return {
    tag: typeTag,
    choices: {
      0x00: new Parser(), // null / no data to read from the buffer

      0x08: new Parser().buffer('value', { length: 8 }), // data8
      0x09: new Parser().buffer('value', { length: 16 }), // data16
      0x0a: new Parser().buffer('value', { length: 24 }), // data24
      0x0b: new Parser().buffer('value', { length: 32 }), // data32
      0x0c: new Parser().buffer('value', { length: 40 }), // data40
      0x0d: new Parser().buffer('value', { length: 48 }), // data48
      0x0e: new Parser().buffer('value', { length: 56 }), // data56
      0x0f: new Parser().buffer('value', { length: 64 }), // data64

      0x10: new Parser().bit8('value', { formatter: formatters.bool }), // bool

      0x18: new Parser().buffer('value', { length: 1 }), // bits8
      0x19: new Parser().buffer('value', { length: 2 }), // bits16
      0x1a: new Parser().buffer('value', { length: 3 }), // bits24
      0x1b: new Parser().buffer('value', { length: 4 }), // bits32
      0x1c: new Parser().buffer('value', { length: 5 }), // bits40
      0x1d: new Parser().buffer('value', { length: 6 }), // bits48
      0x1e: new Parser().buffer('value', { length: 7 }), // bits56
      0x1f: new Parser().buffer('value', { length: 8 }), // bits64

      0x20: new Parser().uint8('value'), // uint8
      0x21: new Parser().uint16le('value'), // uint16
      0x22: new Parser().bit24('value'), // uint24 / TODO?
      0x23: new Parser().uint32le('value'), // uint32
      0x24: new Parser().uint32le('$value').bit8('$value2'), // uint40 / TODO
      0x25: new Parser().uint32le('$value').bit16('$value2'), // uint48 / TODO
      0x26: new Parser().uint32le('$value').bit24('$value2'), // uint56 / TODO
      0x27: new Parser().uint64le('value'), // uint64

      0x28: new Parser().int8('value'), // int8
      0x29: new Parser().int16le('value'), // int16
      0x2a: new Parser().bit24('value'), // int24 / TODO?
      0x2b: new Parser().int32le('value'), // int32
      0x2c: new Parser().int32le('$value').bit8('$value2'), // int40 / TODO
      0x2d: new Parser().int32le('$value').bit16('$value2'), // int48 / TODO
      0x2e: new Parser().int32le('$value').bit24('$value2'), // int56 / TODO
      0x2f: new Parser().int64le('value'), // int64

      0x30: new Parser().uint8('value'), // enum8
      0x31: new Parser().uint16le('value'), // enum16

      0x38: new Parser().floatle('value'), // sfloat / TODO?
      0x39: new Parser().floatle('value'), // float
      0x3a: new Parser().doublele('value'), // double

      0x41: new Parser().uint8('$length').buffer('value', { length: '$length' }), // ostr
      0x42: new Parser().uint8('$length').string('value', { length: '$length' }), // cstr
      0x43: new Parser().uint16le('$length').buffer('value', { length: '$length' }), // lostr
      0x44: new Parser().uint16le('$length').string('value', { length: '$length' }), // lcstr

      ...(complex ? {
        0x48: new Parser().uint8('$el_type').uint16le('$el_num') // array
          .array('value', { length: '$el_num', type: new Parser()
            .choice(zclAttrValueChoice('$el_type', false))
          }),
        // 0x4c: new Parser().struct('struct', { length: x }), // TODO / struct

        0x50: new Parser().uint8('$el_type').uint16le('$el_num') // set
          .array('value', { length: '$el_num', type: new Parser()
            .choice(zclAttrValueChoice('$el_type', false))
          }),
        0x51: new Parser().uint8('$el_type').uint16le('$el_num') // bag
          .array('value', { length: '$el_num', type: new Parser()
            .choice(zclAttrValueChoice('$el_type', false))
          })
      } : {}),

      0xe0: new Parser() // time
        .nest('value', {
          type: new Parser()
            .uint8('hours')
            .uint8('mins')
            .uint8('secs')
            .uint8('csecs')
        }),
      0xe1: new Parser() // date
        .nest('value', {
          type: new Parser()
            .uint8('year')
            .uint8('month')
            .uint8('day')
            .uint8('weekd')
        }),
      0xe2: new Parser().uint32le('value'), // utc

      0xe8: new Parser().buffer('value', { length: 2 }), // cluster_id
      0xe9: new Parser().buffer('value', { length: 2 }), // attr_id
      0xea: new Parser().buffer('value', { length: 4 }), // bacnet_oid

      0xf0: new Parser().buffer('value', { length: 8 }), // ieee_addr
      0xf1: new Parser().buffer('value', { length: 16 }) // security_key
    }
  };
}

// Capability Information (Named Parser / Not Exposed!)
// ATTENTION: Sometimes loading this named parser results in a __parser_cinfo not defined, thus the const is used instead
const cinfoParser = new Parser()
  .namely('cinfo')
  .bit1('alloc', { formatter: formatters.bool })
  .bit1('security', { formatter: formatters.bool })
  .bit2('$unused')
  .bit1('idle_rx', { formatter: formatters.bool })
  .bit1('power', { formatter: formatters.bool })
  .bit1('fdd', { formatter: formatters.bool })
  .bit1('alt_coord', { formatter: formatters.bool });

// ZigBee Cluster Library Attributes
// ATTENTION: cannot be made into a named sub-parser, as type must be a Parser object if the variable name is omitted
const zclAttrsParser = new Parser()
  .array('attrs', {
    readUntil: 'eof',
    type: new Parser()
      .buffer('id', { length: 2 })
      .choice({
        tag: function() {
          return this.$parent.cmd.id[0] !== 0x00 ? 1 : 0; // Read Attributes
        },
        defaultChoice: new Parser(), // optional
        choices: {
          1: new Parser()
            .choice({
              tag: '$parent.cmd.id[0]',
              defaultChoice: new Parser(), // optional
              choices: { 0x01: new Parser().buffer('status', { length: 1 }) } // Read Attributes Response
            })
            .buffer('type', { length: 1 })
            .choice(zclAttrValueChoice())
        }
      })
  });

const parsers = {};

// ZigBee Device Profile
parsers.zbee_zdp = new Parser()
  .namely('zbee_zdp')
  .useContextVars()
  .uint8('seqno')
  .choice(optional({
    tag: function() {
      return this.$parent.cluster.readUInt16LE(0) & 0x8000; // Responses
    },
    type: new Parser()
      .buffer('status', { length: 1 }) // le
  }))
  .choice({
    tag: function() {
      return this.$parent.cluster.readUInt16LE(0);
    },
    choices: {
      0x0000: new Parser() // Network Address Request
        .buffer('ext_addr', { length: 8 }) // le
        .buffer('req_type', { length: 1 })
        .uint8('index'),
      0x8000: new Parser() // Network Address Response
        .buffer('ext_addr', { length: 8 }) // le
        .buffer('nwk_addr', { length: 2 }), // le

      0x0001: new Parser() // Ext. Device ID Request
        .buffer('nwk_addr', { length: 2 }) // le
        .buffer('req_type', { length: 1 })
        .uint8('index'),
      0x8001: new Parser() // Ext. Device ID Response
        .buffer('ext_addr', { length: 8 }) // le
        .buffer('nwk_addr', { length: 2 }), // le

      0x0002: new Parser() // Node Descriptor Request
        .buffer('nwk_addr', { length: 2 }), // le
      0x8002: new Parser() // Node Descriptor Response
        .buffer('nwk_addr', { length: 2 }) // le
        .nest('node', {
          type: new Parser()
            .nest('freq', {
              type: new Parser()
                .bit1('eu_sub_ghz', { formatter: formatters.bool })
                .bit1('mhz2400', { formatter: formatters.bool })
                .bit1('mhz900', { formatter: formatters.bool })
                .bit1('mhz868', { formatter: formatters.bool })
                .bit5('$unused')
                .bit1('frag_support', { formatter: formatters.bool })
                .bit1('user', { formatter: formatters.bool })
                .bit1('complex', { formatter: formatters.bool })
                .bit3('type')
            })
            .nest('cinfo', { type: 'cinfo' })
            .buffer('manufacturer', { length: 2 }) // le
            .uint8('max_buffer')
            .uint8('max_incoming_transfer')
            .nest('server', {
              type: new Parser()
                .bit7('stack_compliance_revision')
                .bit2('$unused')
                .bit1('nwk_mgr', { formatter: formatters.bool })
                .bit1('bak_disc', { formatter: formatters.bool })
                .bit1('pri_disc', { formatter: formatters.bool })
                .bit1('bak_bind', { formatter: formatters.bool })
                .bit1('pri_bind', { formatter: formatters.bool })
                .bit1('bak_trust', { formatter: formatters.bool })
                .bit1('pri_trust', { formatter: formatters.bool })
            })
            .skip(1)
            .uint16le('max_outgoing_transfer')
            .nest('dcf', {
              type: new Parser()
                .bit6('$unused')
                .bit1('esdla', { formatter: formatters.bool })
                .bit1('eaela', { formatter: formatters.bool })
            })
        }),

      0x0004: new Parser() // Simple Descriptor Request
        .buffer('nwk_addr', { length: 2 }) // le
        .uint8('endpoint'),
      0x8004: new Parser() // Simple Descriptor Response
        .buffer('nwk_addr', { length: 2 })
        .uint8('simple_length')
        .buffer('simple_desc', { length: 'simple_length' }),

      0x0005: new Parser() // Active Endpoint Request
        .buffer('nwk_addr', { length: 2 }), // le
      0x8005: new Parser() // Active Endpoint Response
        .buffer('nwk_addr', { length: 2 }) // le
        .uint8('ep_count')
        .array('endpoints', {
          length: 'ep_count',
          type: 'uint8'
        }),

      0x0006: new Parser() // Match Descriptor Request
        .buffer('nwk_addr', { length: 2 }) // le
        .buffer('profile', { length: 2 }) // le
        .uint8('in_count')
        .array('in_clusters', {
          length: 'in_count',
          formatter: array => array.map(item => item.cluster_id),
          type: new Parser()
            .buffer('cluster_id', { length: 2 }) // le
        })
        .uint8('out_count')
        .array('out_clusters', {
          length: 'out_count',
          formatter: array => array.map(item => item.cluster_id),
          type: new Parser()
            .buffer('cluster_id', { length: 2 }) // le
        }),
      0x8006: new Parser() // Match Descriptor Response
        .buffer('nwk_addr', { length: 2 }) // le
        .uint8('ep_count')
        .array('endpoints', {
          length: 'ep_count',
          type: 'uint8'
        }),

      0x0013: new Parser() // Device Announcement
        .buffer('nwk_addr', { length: 2 }) // le
        .buffer('ext_addr', { length: 8 }) // le
        .nest('cinfo', { type: 'cinfo' }),

      0x0021: new Parser() // Bind Request
        .buffer('src64', { length: 8 }) // le
        .uint8('src_ep')
        .buffer('cluster', { length: 2 }) // le
        .buffer('addr_mode', { length: 1 })
        .buffer('dst64', { length: 8 }) // le
        .uint8('dst_ep'),
      0x8021: new Parser(), // Bind Response

      0x0031: new Parser() // LQI Request
        .uint8('index'),
      0x8031: new Parser() // LQI Response
        .uint8('table_size')
        .uint8('index')
        .uint8('table_count')
        .array('entries', {
          length: 'table_count',
          type: new Parser()
            .buffer('extended_pan', { length: 8 }) // le
            .buffer('ext_addr', { length: 8 }) // le
            .buffer('addr', { length: 2 }) // le
            .bit1('$unused')
            .bit3('relationship')
            .bit2('idle_rx', { formatter: formatters.bool })
            .bit2('type')
            .bit6('$unused')
            .bit2('permit_joining', { formatter: formatters.bool })
            .uint8('depth')
            .uint8('lqi')
        }),

      0x0032: new Parser() // Routing Table Request
        .uint8('index'),
      0x8032: new Parser() // Routing Table Response
        .choice(optional({
          tag: function() {
            return this.status === 0x00; // 0x84 -> not supported
          },
          type: new Parser()
            .buffer('data', { readUntil: 'eof' }) // TODO
        })),

      0x0034: new Parser() // Leave Request
        .buffer('ext_addr', { length: 8 }) // le
        .nest('leave', {
          type: new Parser()
            .bit1('rejoin', { formatter: formatters.bool })
            .bit1('remove', { formatter: formatters.bool })
            .bit6('$unused')
        }),
      0x8034: new Parser(), // Leave Response

      0x0036: new Parser() // Permit Join Request
        .uint8('duration')
        .uint8('significance')
    }
  });

// ZigBee Cluster Library
parsers.zbee_zcl = new Parser()
  .namely('zbee_zcl')
  .useContextVars()
  .buffer('fcf', { length: 1 }) // frame control field
  .seek(-1)
  .nest('fc', {
    type: new Parser()
      .bit3('$unused')
      .bit1('ddr', { formatter: formatters.bool })
      .bit1('dir')
      .bit1('ms', { formatter: formatters.bool })
      .bit2('type')
  })
  .nest('cmd', {
    type: new Parser()
      .choice({
        tag: function() { return this.$parent.fc.ms ? 1 : 0; },
        defaultChoice: new Parser(), // optional
        choices: { 1: new Parser().buffer('mc', { length: 2 }) } // manufacturer code
      })
      .uint8('tsn')
      .buffer('id', { length: 1 })
      .choice({
        tag: 'id[0]',
        defaultChoice: new Parser(), // optional
        choices: {
          0x0b: new Parser() // Default Response
            .buffer('id_rsp', { length: 1 })
        }
      })
  })
  .choice({
    tag: 'cmd.id[0]',
    choices: {
      0x00: zclAttrsParser, // Read Attributes
      0x01: zclAttrsParser, // Read Attributes Response
      0x02: zclAttrsParser, // Write Attributes
      0x04: new Parser() // Write Attributes Response
        .buffer('status', { length: 1 }),
      0x06: new Parser() // Configure Reporting
        .buffer('attrs', { readUntil: 'eof' }) // TODO remove
        .array('$attrs', { // TODO, in order to properly parse this array, we need knowledge about properties of each attribute, don't parse it right now
          readUntil: () => true, // do not read any data
          type: new Parser()
            .buffer('dir', { length: 1 })
            .buffer('attr_id', { length: 2 })
            .buffer('type', { length: 1 })
            .uint16le('minint')
            .uint16le('maxint')
        }),
      0x07: new Parser() // Configure Reporting Response
        .buffer('status', { length: 1 }),
      0x0a: zclAttrsParser, // Report Attributes
      0x0b: new Parser() // Default Response
        .buffer('status', { length: 1 }),
      0x0c: new Parser() // Discover Attributes
        .buffer('start', { length: 2 })
        .uint8('maxnum'),
      0x0d: new Parser() // Discover Attributes Response
        .skip(1)
        .array('attrs', {
          readUntil: 'eof',
          type: new Parser()
            .buffer('attr_id', { length: 2 })
            .buffer('type', { length: 1 })
        })
    }
  });

// ZigBee Application Support Layer Command Frame
parsers.zbee_aps_cmd = new Parser()
  .namely('zbee_aps_cmd')
  .useContextVars()
  .buffer('id', { length: 1 })
  .choice({
    tag: 'id[0]',
    choices: {
      0x05: new Parser() // Transport Key
        .buffer('key_type', { length: 1 })
        .buffer('key', { length: 16 })
        .uint8('seqno')
        .buffer('dst', { length: 8 })
        .buffer('src', { length: 8 })
    }
  });

// ZigBee Secure / Encrypted Application Support Layer Frame
parsers.zbee_aps_secure = generateSecureParser('zbee_aps_secure', 15, tempContext => ({
  0x0: new Parser(), // APS Data / TODO
  0x1: new Parser().wrapped('cmd', { // APS Cmd
    type: 'zbee_aps_cmd',
    readUntil: () => true, // do not read any additional data
    wrapper: function() {
      return tempContext.data; // TODO replace with this.$data
    }
  })
}));

// ZigBee Application Support Layer Data
parsers.zbee_aps = new Parser()
  .namely('zbee_aps')
  .useContextVars()
  .saveOffset('$zbee_aadStart')
  .buffer('fcf', { length: 1 }) // frame control field
  .seek(-1)
  .nest('fc', {
    type: new Parser()
      .bit1('ext_header', { formatter: formatters.bool })
      .bit1('ack_req', { formatter: formatters.bool })
      .bit1('security', { formatter: formatters.bool })
      .bit1('ack_format', { formatter: formatters.bool })
      .bit2('delivery')
      .bit2('type')
  })
  .choice(optional({
    tag: function() {
      // if either 0x0 / Data, or 0x2 / Ack with ack_format not set to parse endpoint data
      return this.fc.type === 0x0 || (this.fc.type === 0x2 && !this.fc.ack_format) ? 1 : 0;
    },
    type: new Parser()
      .uint8('dst')
      .buffer('cluster', { length: 2 })
      .buffer('profile', { length: 2 })
      .uint8('src')
  }))
  .uint8('counter')
  .choice({
    tag: function() { return this.fc.security ? 0xF : this.fc.type; },
    formatter: formatters.hoist,
    choices: {
      0x1: new Parser(), // Cmd / TODO
      0xF: new Parser().nest('$hoist', {
        type: 'zbee_aps_secure'
      })
    },
    defaultChoice: new Parser()
      .choice({
        tag: 'fc.type',
        choices: {
          0x02: new Parser() // Ack
        },
        defaultChoice: new Parser()
          .choice({
            tag: function() {
              return this.profile.readUInt16LE(0);
            },
            choices: {
              0x0000: new Parser() // Zigbee Device Profile (ZDP)
                .nest('zbee_zdp', {
                  type: 'zbee_zdp'
                })
            },
            defaultChoice: new Parser()
              .choice({
                tag: function() {
                  return this.cluster.readUInt16LE(0);
                },
                defaultChoice: new Parser() // all ZCL clusters
                  .choice({
                    tag: 'fc.type',
                    choices: {
                      0x00: new Parser().nest('zbee_zcl', { // Data
                        type: 'zbee_zcl'
                      }),
                      0x02: new Parser() // Ack
                    }
                  }),
                choices: {
                  0x0019: new Parser() // ignore OTA Upgrade cluster messages for now / TODO
                    .buffer('data', { readUntil: 'eof' })
                }
              })
          })
      })
  });

// ZigBee Network Layer Command Frame
parsers.zbee_nwk_cmd = new Parser()
  .namely('zbee_nwk_cmd')
  .useContextVars()
  .buffer('id', { length: 1 })
  .choice({
    tag: 'id[0]',
    choices: {
      0x01: new Parser().nest('route', { // Mandy-to-One Route Request
        type: new Parser().nest('opts', {
          type: new Parser()
            .bit1('$unused')
            .bit1('mcast', { formatter: formatters.bool })
            .bit1('dest_ext', { formatter: formatters.bool })
            .bit2('many2one')
            .bit3('$unused')
        })
          .uint8('id')
          .buffer('dest', { length: 2 })
          .uint8('cost')
      }),
      0x02: new Parser() // Route Reply
        .nest('opts', {
          type: new Parser()
            .bit1('$unused')
            .bit1('mcast', { formatter: formatters.bool })
            .bit1('resp_ext', { formatter: formatters.bool })
            .bit1('orig_ext', { formatter: formatters.bool })
            .bit4('$unused')
        })
        .nest('route', {
          type: new Parser()
            .uint8('id')
            .buffer('orig', { length: 2 }) // le
            .buffer('resp', { length: 2 }) // le
            .uint8('cost')
            .choice(optional({
              tag: function() { return this.$parent.opts.orig_ext; },
              type: new Parser()
                .buffer('orig_ext', { length: 8 }) // le
            }))
            .choice(optional({
              tag: function() { return this.$parent.opts.resp_ext; },
              type: new Parser()
                .buffer('resp_ext', { length: 8 }) // le
            }))
        }),
      0x03: new Parser() // Network Status
        .buffer('status', { length: 1 })
        .nest('route', {
          type: new Parser()
            .buffer('dest', { length: 2 }) // le
        }),
      0x04: new Parser() // Leave
        .nest('leave', {
          type: new Parser()
            .bit1('children', { formatter: formatters.bool })
            .bit1('request', { formatter: formatters.bool })
            .bit1('rejoin', { formatter: formatters.bool })
            .bit5('$unused')
        }),
      0x05: new Parser().nest('relay', { // Route Record
        type: new Parser()
          .uint8('count')
          .array('relay', {
            length: 'count',
            type: new Parser()
              .buffer('address', { length: 2 }), // le
            formatter: array => array.map(item => item.address)
          })
      }),
      0x06: new Parser() // Rejoin Request
        .nest('cinfo', { type: cinfoParser }),
      0x07: new Parser() // Rejoin Response
        .buffer('addr', { length: 2 }) // le
        .buffer('status', { length: 1 }),
      0x08: new Parser().nest('link', { // Link Status
        type: new Parser()
          .bit1('$unused')
          .bit1('last', { formatter: formatters.bool })
          .bit1('first', { formatter: formatters.bool })
          .bit5('count')
          .array('items', {
            length: 'count',
            type: new Parser()
              .buffer('address', { length: 2 }) // le
              .bit1('$unused')
              .bit3('outgoing_cost')
              .bit1('$unused')
              .bit3('incoming_cost')
          })
      }),
      0x0b: new Parser() // End Device Timeout Request
        .int8('ed_tmo_req')
        .buffer('ed_config', { length: 1 }),
      0x0c: new Parser() // End Device Timeout Response
        .buffer('status', { length: 1 })
        .nest('ed_prnt_info', {
          type: new Parser()
            .bit5('$unused')
            .bit1('power_negotiation_supported', { formatter: formatters.bool })
            .bit1('ed_tmo_req_keepalive', { formatter: formatters.bool })
            .bit1('mac_data_poll_keepalive', { formatter: formatters.bool })
        })
    }
  });

// ZigBee Command Frame
parsers.zbee_cmd = new Parser()
  .namely('zbee_cmd')
  .useContextVars()
  .buffer('id', { length: 1 })
  .choice({
    tag: 'id[0]',
    choices: {
      0x01: new Parser() // Association Request
        .bit1('alloc_addr', { formatter: formatters.bool })
        .bit1('sec_capable', { formatter: formatters.bool })
        .bit2('$unused')
        .bit1('idle_rx', { formatter: formatters.bool })
        .bit1('power_src')
        .bit1('device_type')
        .bit1('alt_coord', { formatter: formatters.bool }),
      0x02: new Parser() // Association Response
        .nest('assoc', {
          type: new Parser()
            .buffer('addr', { length: 2 }) // le
            .buffer('status', { length: 1 })
        }),
      0x04: new Parser(), // Data Request
      0x05: new Parser() // Route Record
        .uint8('relay_count')
        .buffer('relay_device', { length: 2 }),
      0x07: new Parser() // Beacon Request
    }
  });

// ZigBee Secure / Encrypted Network Layer Frame
parsers.zbee_nwk_secure = generateSecureParser('zbee_nwk_secure', function() {
  const fc = parent(this, 'fc');
  return 22 + (fc.ext_dst ? 8 : 0) + (fc.ext_src ? 8 : 0) + (fc.src_route ? 2 + (parent(this, 'relay').count * 2) : 0);
}, tempContext => ({
  0x0: new Parser().wrapped('zbee_aps', { // NWK Data
    type: 'zbee_aps',
    readUntil: () => true, // do not read any additional data
    wrapper: function() {
      return tempContext.data; // TODO replace with this.$data
    }
  }),
  0x1: new Parser().wrapped('cmd', { // NWK Cmd
    type: 'zbee_nwk_cmd',
    readUntil: () => true, // do not read any additional data
    wrapper: function() {
      return tempContext.data; // TODO replace with this.$data
    }
  })
}));

// ZigBee Network Layer Data
parsers.zbee_nwk = new Parser()
  .namely('zbee_nwk')
  .useContextVars()
  .saveOffset('$zbee_aadStart')
  .buffer('fcf', { length: 2 }) // le
  .seek(-2)
  .nest('fc', {
    type: new Parser()
      .bit2('discovery')
      .bit4('proto_version')
      .bit2('type')
      .bit2('$unused')
      .bit1('end_device_initiator', { formatter: formatters.bool })
      .bit1('ext_src', { formatter: formatters.bool })
      .bit1('ext_dst', { formatter: formatters.bool })
      .bit1('src_route', { formatter: formatters.bool })
      .bit1('security', { formatter: formatters.bool })
      .bit1('multicast', { formatter: formatters.bool })
  })
  .buffer('dst', { length: 2 }) // le
  .buffer('src', { length: 2 }) // le
  .uint8('radius')
  .uint8('seqno')
  .choice({
    tag: function() { return this.fc.src_route ? 1 : 0; },
    defaultChoice: new Parser(), // optional
    choices: {
      1: new Parser().nest('relay', {
        type: new Parser()
          .uint8('count')
          .uint8('index')
          .array('relay', {
            length: 'count',
            type: new Parser()
              .buffer('address', { length: 2 }), // le
            formatter: array => array.map(item => item.address)
          })
      })
    }
  })
  .choice({
    tag: function() { return this.fc.ext_dst ? 1 : 0; },
    defaultChoice: new Parser(), // optional
    choices: { 1: new Parser().buffer('dst64', { length: 8 }) } // le
  })
  .choice({
    tag: function() { return this.fc.ext_src ? 1 : 0; },
    defaultChoice: new Parser(), // optional
    choices: { 1: new Parser().buffer('src64', { length: 8 }) } // le
  })
  .choice({
    tag: function() { return this.fc.security ? 0xF : this.fc.type; },
    formatter: formatters.hoist,
    choices: {
      0x0: new Parser().nest('zbee_aps', { // Data
        type: 'zbee_aps'
      }),
      0x1: new Parser().nest('cmd', { // Cmd
        type: 'zbee_nwk_cmd'
      }),
      0xF: new Parser().nest('$hoist', {
        type: 'zbee_nwk_secure'
      })
    }
  })
  .seek(4); // skip 4 bytes mic, as we already parsed it before;

// ZigBee Beacon
parsers.zbee_beacon = new Parser()
  .namely('zbee_beacon')
  .useContextVars()
  .buffer('protocol', { length: 1 })
  .bit1('end_dev', { formatter: formatters.bool })
  .bit4('depth')
  .bit1('router', { formatter: formatters.bool })
  .bit4('version')
  .bit4('profile')
  .buffer('ext_panid', { length: 8 }) // le
  .buffer('tx_offset', { length: 3 }) // le,
  .buffer('update_id', { length: 1 });

// IEEE 802.15.4 Low-Rate Wireless PAN (WPAN)
parsers.wpan = new Parser()
  .namely('wpan')
  .useContextVars()
  .saveOffset('$wpanStart')
  .pointer('$wpanData', {
    offset: '$wpanStart',
    type: new Parser()
      .buffer('data', { readUntil: 'eof' }),
    formatter: parser => parser.data // do not nest pointer
  })
  .buffer('$wpanLength', {
    readUntil: () => true, // do not read any data
    formatter: function() {
      return this.$wpanData.length;
    }
  })
  .buffer('fcf', { length: 2 }) // frame control field
  .seek(-2)
  .nest('fc', {
    type: new Parser()
      .bit1('reserved', { formatter: formatters.bool })
      .bit1('pan_id_compression', { formatter: formatters.bool })
      .bit1('ack_request', { formatter: formatters.bool })
      .bit1('pending', { formatter: formatters.bool })
      .bit1('security', { formatter: formatters.bool })
      .bit3('type')
      .bit2('src_addr_mode')
      .bit2('version')
      .bit2('dst_addr_mode')
      .bit1('ie_present', { formatter: formatters.bool })
      .bit1('seqno_suppression', { formatter: formatters.bool })
  })
  .choice({
    tag: function() { return this.fc.seqno_suppression ? 1 : 0; },
    choices: {
      0: new Parser()
        .uint8('seq_no'),
      1: new Parser()
    }
  })
  .choice({
    tag: 'fc.type',
    choices: {
      0x2: new Parser() // Ack
    },
    defaultChoice: new Parser()
      /* Implements Table 7-6 of IEEE 802.15.4-2015
        *
        *      Destination Address  Source Address  Destination PAN ID  Source PAN ID   PAN ID Compression
        *-------------------------------------------------------------------------------------------------
        *  1.  Not Present          Not Present     Not Present         Not Present     0
        *  2.  Not Present          Not Present     Present             Not Present     1
        *  3.  Present              Not Present     Present             Not Present     0
        *  4.  Present              Not Present     Not Present         Not Present     1
        *
        *  5.  Not Present          Present         Not Present         Present         0
        *  6.  Not Present          Present         Not Present         Not Present     1
        *
        *  7.  Extended             Extended        Present             Not Present     0
        *  8.  Extended             Extended        Not Present         Not Present     1
        *
        *  9.  Short                Short           Present             Present         0
        * 10.  Short                Extended        Present             Present         0
        * 11.  Extended             Short           Present             Present         0
        *
        * 12.  Short                Extended        Present             Not Present     1
        * 13.  Extended             Short           Present             Not Present     1
        * 14.  Short                Short           Present             Not Present     1
        */
      .choice(optional({
        tag: function() {
          if (this.fc.version === 0x0 || this.fc.version === 0x1) { // IEEE Std 802.15.4-2003, IEEE Std 802.15.4-2005
            if (this.fc.dst_addr_mode !== 0x0 && this.fc.src_addr_mode !== 0x0) {
              return true;
            } else if (this.fc.pan_id_compression) {
              return false; // invalid pan_id_compression!
            } else {
              return this.fc.dst_addr_mode !== 0x0 && this.fc.src_addr_mode === 0x0;
            }
          } else if (this.fc.version === 0x2) { // IEEE Std 802.15.4-2015, determine based on Table 7-6
            if (this.fc.type === 0x0 || this.fc.type === 0x1 || this.fc.type === 0x2 || this.fc.type === 0x3) { // Beacon, Data, Ack or Cmd
              return !( // define the conditions where the Dst. PAN ID is *NOT* present
                (this.fc.dst_addr_mode === 0x0 && this.fc.src_addr_mode === 0x0 && !this.fc.pan_id_compression) || // row 1.
                (this.fc.dst_addr_mode !== 0x0 && this.fc.src_addr_mode === 0x0 && this.fc.pan_id_compression) || // row 4.
                (this.fc.dst_addr_mode === 0x0 && this.fc.src_addr_mode !== 0x0) || // row 5. + 6.
                (this.fc.dst_addr_mode === 0x3 && this.fc.src_addr_mode === 0x3 && this.fc.pan_id_compression) // row 8.
              );
            }
          }

          return false;
        },
        type: new Parser()
          .buffer('dst_pan', { length: 2 }) // le
      }))
      .choice({
        tag: 'fc.dst_addr_mode',
        choices: {
          0x0: new Parser(), // None
          0x2: new Parser() // Short
            .buffer('dst16', { length: 2 }), // le
          0x3: new Parser() // Long / Ext.
            .buffer('dst64', { length: 8 }) // le
        }
      })
      .choice(optional({
        tag: function() {
          if (this.fc.version === 0x0 || this.fc.version === 0x1) { // IEEE Std 802.15.4-2003, IEEE Std 802.15.4-2005
            if (this.fc.dst_addr_mode !== 0x0 && this.fc.src_addr_mode !== 0x0) {
              return !this.fc.pan_id_compression;
            } else if (this.fc.pan_id_compression) {
              return false; // invalid pan_id_compression!
            } else {
              return this.fc.dst_addr_mode === 0x0 && this.fc.src_addr_mode !== 0x0;
            }
          } else if (this.fc.version === 0x2) { // IEEE Std 802.15.4-2015, determine based on Table 7-6
            if (this.fc.type === 0x0 || this.fc.type === 0x1 || this.fc.type === 0x2 || this.fc.type === 0x3) { // Beacon, Data, Ack or Cmd
              return ( // define the conditions where the Src. PAN ID *IS* present
                (this.fc.dst_addr_mode === 0x0 && this.fc.src_addr_mode !== 0x0 && !this.fc.pan_id_compression) || // row 5.
                (this.fc.dst_addr_mode === 0x2 && this.fc.src_addr_mode === 0x2 && !this.fc.pan_id_compression) || // row 9.
                (this.fc.dst_addr_mode === 0x2 && this.fc.src_addr_mode === 0x3 && !this.fc.pan_id_compression) || // row 10.
                (this.fc.dst_addr_mode === 0x3 && this.fc.src_addr_mode === 0x2 && !this.fc.pan_id_compression) // row 11.
              );
            }
          }

          return false;
        },
        type: new Parser()
          .buffer('src_pan', { length: 2 }) // le
      }))
      .choice({
        tag: 'fc.src_addr_mode',
        choices: {
          0x0: new Parser(), // None
          0x2: new Parser() // Short
            .buffer('src16', { length: 2 }), // le
          0x3: new Parser() // Long / Ext.
            .buffer('src64', { length: 8 }) // le
        }
      })
      .choice({
        tag: 'fc.type',
        choices: {
          0x0: new Parser() // Beacon
            .bit1('assoc_permit', { formatter: formatters.bool })
            .bit1('bcn_coord', { formatter: formatters.bool })
            .bit1('$unused')
            .bit1('battery_ext', { formatter: formatters.bool })
            .bit4('cap')
            .bit4('superframe_order')
            .bit4('beacon_order')
            .buffer('gts', { length: 2 })
            .nest('zbee_beacon', { type: 'zbee_beacon' }),
          0x1: new Parser() // Data
            .nest('zbee_nwk', { type: 'zbee_nwk' }),
          0x3: new Parser() // Command
            .nest('cmd', { type: 'zbee_cmd' })
        }
      })
  })
  .buffer('fcs', {
    length: 2,
    assert: assertFunction('a mismatch to the calculated CRC', function(fcs) {
      // provide the option to skip the FCS check, as sometimes frames come with a CC24xx metadata instead of a FCS (i.e. some sniffers validate the CRC
      // themselves and replace the FCS with other data, such as LQI / RSSI). in case the packet is part of a ZEP, the FCS is checked when encoding the ZEP package.
      // otherwise calculate the CRC-16/CCITT style for the IEEE 802.15.4 FCS (xor-in & out = 0x0000, poly = 0x1021)
      return env.ZBTK_PARSE_SKIP_FCS_CHECK || parent(this, '$zep') || fcs.equals(crc(this.$wpanData.subarray(0, this.$wpanLength - 2), 0x0000, 0x0000));
    })
  });

// ZigBee Encapsulation Protocol
const zepParser = new Parser()
  .useContextVars()
  .buffer('$zep', { // mark ZEP packages (to determine "length" for WPAN)
    readUntil: () => true, // do not read any data
    formatter: function() {
      return true;
    }
  })
  .string('protocol_id', { length: 2 })
  .uint8('version')
  .bit8('type')
  .uint8('channel_id')
  .uint16('device_id')
  .bit8('lqi_mode')
  .uint8('lqi')
  .buffer('time', { length: 8, formatter: formatters.datetime })
  .uint32('seqno')
  .seek(10) // reserved
  .uint8('length');

parsers.zep = new Parser()
  .namely('zep')
  .useContextVars()
  .nest({ type: zepParser })
  .nest('wpan', { type: 'wpan' });

const zepWpanBufferParser = new Parser()
  .useContextVars()
  .nest({ type: zepParser })
  .buffer('wpan', { readUntil: 'eof' });
/**
 * Parse ZigBee Encapsulation Protocol (ZEP) packet data, without parsing the included IEEE 802.15.4
 * Low-Rate Wireless PAN (WPAN) packet, which will be returned as a raw buffer.
 *
 * @param {Buffer} data the packet data to parse
 * @returns {object} the parsed packet data
 */
export function parseZep(data) {
  return zepWpanBufferParser.parse(data);
}

/**
 * Parse ZigBee packet data.
 *
 * By default it will parse the data as a IEEE 802.15.4 Low-Rate Wireless PAN (WPAN) packet.
 * Other packet types, like ZigBee Encapsulation Protocol (ZEP) packets, can be parsed by specifying the type.
 *
 * @param {Buffer} data the packet data to parse
 * @param {string} [type='wpan'] the type of packet to parse
 * @returns {object} the parsed packet data
 */
export function parse(data, type = 'wpan') {
  if (!(type in parsers)) {
    throw new TypeError(`Unknown packet type: ${type}`);
  }

  const result = Object.defineProperty(parsers[type].parse(data), 'toString', {
    value: function() { return jsonStringify(this); },
    configurable: true
  });

  if (env.ZBTK_PARSE_KEEP_TEMP) {
    return result;
  }

  // deep clean up / remove any $ temporary fields / variables from the result
  return traverse(result).forEach(function() {
    if (this.key && this.key.startsWith('$')) {
      this.remove();
    }
  });
}

export default parse;

import { stdinMiddleware, jsonStringify } from './utils.js';
export const commands = [
  {
    command: 'parse [data]',
    desc: 'Packet Binary Parser',
    builder: yargs => stdinMiddleware(yargs
      .option('type', {
        alias: 't',
        desc: 'Type of packet to parse',
        type: 'string',
        choices: Object.keys(parsers),
        default: 'wpan'
      }), { desc: 'Data to parse' })
      .example('$0 parse --type zep 4558020113fffe0029d84f48995f78359c000a91aa000000000000000000000502003ffecb', 'Parse the given data as a ZigBee Encapsulation Protocol (ZEP) packet')
      .example('echo -n 4558020113fffe0029d84f48995f78359c000a91aa000000000000000000000502003ffecb | $0 parse --type zep', 'Parse the given data from stdin as a ZigBee Encapsulation Protocol (ZEP) packet')
      .version(false)
      .help(),
    handler: argv => {
      console.log(`${parse(argv.data, argv.type)}`);
    }
  }
];

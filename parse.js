import { env } from 'node:process';
import { Buffer } from 'node:buffer';
import { Parser } from 'binary-parser';
import { pks, decrypt } from './crypto.js';
import { crc, key as hashKey } from './hash.js';
import { fromHex } from './utils.js';
import { types } from './type.js';

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
  },
  unwrap: function(array) {
    return array.map(item => item.$unwrap || item);
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

function wrappedDecryptedPayload(name, type) {
  return new Parser().wrapped(name, {
    type,
    length: 0,
    wrapper: function() {
      return this.$data;
    }
  });
}

function generateSecureParser(name, aadLength, choices) {
  const rawData = new Parser().buffer('data', {
    length: 0,
    formatter: function() {
      return this.$data;
    }
  });

  return new Parser()
    .namely(name)
    .useContextVars()
    .nest('sec', {
      type: new Parser()
        .buffer('scf', { length: 1 }) // le
        .seek(-1)
        .nest('sc', {
          type: new Parser()
            .skipBits(1)
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
      default: rawData,
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
          length: 0,
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
              this.$data = decrypt;
              return parent(this, 'fc').type;
            }
          },
          choices: {
            ...choices,
            0xF: rawData
          }
        })
    }));
}

const zclAttrValueParser = new Parser()
  .buffer('value', {
    readUntil: 'eof',
    formatter: function(buffer) {
      const type = this.type[0];
      const codec = types.data[type];
      if (!codec) {
        throw new RangeError(`Unsupported ZCL attribute type ${type}`);
      }
      const { value, offset } = codec.read(buffer);
      this.$valueLength = offset;
      return value;
    }
  })
  .seek('$valueLength');

// Capability Information
const cinfoParser = new Parser()
  .bit1('alloc', { formatter: formatters.bool })
  .bit1('security', { formatter: formatters.bool })
  .skipBits(2)
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
              tag: function() { return this.$parent.cmd.id[0]; },
              defaultChoice: new Parser(), // optional
              choices: { 0x01: new Parser().buffer('status', { length: 1 }) } // Read Attributes Response
            })
            .choice(optional({
              tag: function() { return !this.status?.[0]; },
              type: new Parser()
                .buffer('type', { length: 1 })
                .choice(optional({
                  tag: function() { return this.type[0] !== 0x00; },
                  type: zclAttrValueParser
                }))
            }))
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
                .skipBits(5)
                .bit1('frag_support', { formatter: formatters.bool })
                .bit1('user', { formatter: formatters.bool })
                .bit1('complex', { formatter: formatters.bool })
                .bit3('type')
            })
            .nest('cinfo', { type: cinfoParser })
            .buffer('manufacturer', { length: 2 }) // le
            .uint8('max_buffer')
            .uint8('max_incoming_transfer')
            .nest('server', {
              type: new Parser()
                .bit7('stack_compliance_revision')
                .skipBits(2)
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
                .skipBits(6)
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
          type: new Parser()
            .buffer('$unwrap', { length: 2 }), // le
          formatter: formatters.unwrap
        })
        .uint8('out_count')
        .array('out_clusters', {
          length: 'out_count',
          type: new Parser()
            .buffer('$unwrap', { length: 2 }), // le
          formatter: formatters.unwrap
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
        .nest('cinfo', { type: cinfoParser }),

      0x001f: new Parser() // Parent Announce
        .uint8('n_children')
        .array('children', {
          length: 'n_children',
          type: new Parser()
            .buffer('ext_addr', { length: 8 }) // le
        }),

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
            .skipBits(1)
            .bit3('relationship')
            .bit2('idle_rx', { formatter: formatters.bool })
            .bit2('type')
            .skipBits(6)
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
            .skipBits(6)
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
      .skipBits(3)
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
        tag: function() { return this.id[0]; },
        defaultChoice: new Parser(), // optional
        choices: {
          0x0b: new Parser() // Default Response
            .buffer('id_rsp', { length: 1 })
        }
      })
  })
  .choice({
    tag: function() { return this.cmd.id[0]; },
    choices: {
      0x00: zclAttrsParser, // Read Attributes
      0x01: zclAttrsParser, // Read Attributes Response
      0x02: zclAttrsParser, // Write Attributes
      0x04: new Parser() // Write Attributes Response
        .buffer('status', { length: 1 }),
      0x06: new Parser() // Configure Reporting
        .buffer('attrs', { readUntil: 'eof' })
        .array('$attrs', { // TODO handle direction and reportable change before decoding records
          length: 0,
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
        }),
      0x12: new Parser() // Discover Commands Received Response
        .buffer('dis', { length: 1 })
        .array('cs', {
          readUntil: 'eof',
          type: new Parser()
            .buffer('$unwrap', { length: 1 }),
          formatter: formatters.unwrap
        })
    }
  });

// ZigBee Application Support Layer Command Frame
parsers.zbee_aps_cmd = new Parser()
  .namely('zbee_aps_cmd')
  .useContextVars()
  .buffer('id', { length: 1 })
  .choice({
    tag: function() { return this.id[0]; },
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
parsers.zbee_aps_secure = generateSecureParser('zbee_aps_secure', 15, {
  0x0: new Parser(), // APS Data / TODO
  0x1: wrappedDecryptedPayload('cmd', 'zbee_aps_cmd')
});

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
    tag: function() { return this.id[0]; },
    choices: {
      0x01: new Parser().nest('route', { // Mandy-to-One Route Request
        type: new Parser().nest('opts', {
          type: new Parser()
            .skipBits(1)
            .bit1('mcast', { formatter: formatters.bool })
            .bit1('dest_ext', { formatter: formatters.bool })
            .bit2('many2one')
            .skipBits(3)
        })
          .uint8('id')
          .buffer('dest', { length: 2 })
          .uint8('cost')
      }),
      0x02: new Parser() // Route Reply
        .nest('opts', {
          type: new Parser()
            .skipBits(1)
            .bit1('mcast', { formatter: formatters.bool })
            .bit1('resp_ext', { formatter: formatters.bool })
            .bit1('orig_ext', { formatter: formatters.bool })
            .skipBits(4)
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
            .skipBits(5)
        }),
      0x05: new Parser().nest('relay', { // Route Record
        type: new Parser()
          .uint8('count')
          .array('relay', {
            length: 'count',
            type: new Parser()
              .buffer('$unwrap', { length: 2 }), // le
            formatter: formatters.unwrap
          })
      }),
      0x06: new Parser() // Rejoin Request
        .nest('cinfo', { type: cinfoParser }),
      0x07: new Parser() // Rejoin Response
        .buffer('addr', { length: 2 }) // le
        .buffer('status', { length: 1 }),
      0x08: new Parser().nest('link', { // Link Status
        type: new Parser()
          .skipBits(1)
          .bit1('last', { formatter: formatters.bool })
          .bit1('first', { formatter: formatters.bool })
          .bit5('count')
          .array('items', {
            length: 'count',
            type: new Parser()
              .buffer('address', { length: 2 }) // le
              .skipBits(1)
              .bit3('outgoing_cost')
              .skipBits(1)
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
            .skipBits(5)
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
    tag: function() { return this.id[0]; },
    choices: {
      0x01: new Parser() // Association Request
        .bit1('alloc_addr', { formatter: formatters.bool })
        .bit1('sec_capable', { formatter: formatters.bool })
        .skipBits(2)
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
}, {
  0x0: wrappedDecryptedPayload('zbee_aps', 'zbee_aps'),
  0x1: wrappedDecryptedPayload('cmd', 'zbee_nwk_cmd')
});

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
      .skipBits(2)
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
              .buffer('$unwrap', { length: 2 }), // le
            formatter: formatters.unwrap
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

export const BROADCAST_PAN_ID = Buffer.from([0xff, 0xff]);

let filterDstPan;
if (env.ZBTK_PARSE_FILTER_DST_PAN) {
  // the endianess in ZigBee packets is reversed, compared to what commonly displayed to the user
  filterDstPan = fromHex(env.ZBTK_PARSE_FILTER_DST_PAN, /* reverse = */true);
  if (filterDstPan?.length !== 2) {
    console.warn(`Invalid filter destination PAN ID: ${env.ZBTK_PARSE_FILTER_DST_PAN}, no filter will be applied`);
    filterDstPan = undefined;
  }
}

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
    length: 0,
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
      .choice(optional({
        tag: function() { // filter dst_pan
          let dstPan;
          if (!filterDstPan || !(dstPan = this.dst_pan) || BROADCAST_PAN_ID.equals(dstPan) || filterDstPan.equals(dstPan)) {
            return true; // continue parsing
          }

          this.$filterDstPan = true; // mark that the dst_pan was filtered, so we can skip the FCS check later
          return false;
        },
        type: new Parser()
          .choice({
            tag: 'fc.type',
            choices: {
              0x0: new Parser() // Beacon
                .bit1('assoc_permit', { formatter: formatters.bool })
                .bit1('bcn_coord', { formatter: formatters.bool })
                .skipBits(1)
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
      }))
  })
  .buffer('fcs', {
    length: 2,
    assert: assertFunction('a mismatch to the calculated CRC', function(fcs) {
      // provide the option to skip the FCS check, as sometimes frames come with a CC24xx metadata instead of a FCS (i.e. some sniffers validate the CRC
      // themselves and replace the FCS with other data, such as LQI / RSSI). in case the packet is part of a ZEP, the FCS is checked when encoding the ZEP package.
      // otherwise calculate the CRC-16/CCITT style for the IEEE 802.15.4 FCS (xor-in & out = 0x0000, poly = 0x1021)
      return env.ZBTK_PARSE_SKIP_FCS_CHECK || this.$filterDstPan || parent(this, '$zep') || fcs.equals(crc(this.$wpanData.subarray(0, this.$wpanLength - 2), 0x0000, 0x0000));
    })
  });

// ZigBee Encapsulation Protocol
const zepParser = new Parser()
  .useContextVars()
  .buffer('$zep', { // mark ZEP packages (to determine "length" for WPAN)
    length: 0,
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

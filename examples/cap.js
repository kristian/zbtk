import { process as processCap } from '../cap.js';

// set pre-configured keys for automatic decryption either via the
// ZBTK_CRYPTO_PKS / ZBTK_CRYPTO_WELL_KNOWN_PKS env. variables or:
import { pk } from '../crypto.js';
pk(Buffer.from('52f0fe8052ebb35907daa243c95a2ff4', 'hex'));

const capEmitter = await processCap('examples/trace.pcap', {
  unwrapLayers: ['eth', 'ip4', 'udp', 'zep'], // the layers to unwrap to reach the WPAN/ZigBee layer for processing, defaults to []
  bufferSize: 10 * 1024 * 1024, // in bytes, defaults to 10 MB
  emit: ['attribute'], // defaults to "attribute", one, multiple of: "data", "packet", "attribute"
  out: {
    log: ['packet'], // defaults to ['info'], true to emit what in the emit array + info logging, or array / string similar to emit options
    mqtt: { // defaults to null
      url: 'mqtt://localhost:1883', // see https://www.npmjs.com/package/mqtt#connect url
      options: { // see https://www.npmjs.com/package/mqtt#connect options
        username: 'user',
        password: 'pass'
      },
      client: null, // as an alternative for providing out.mqtt.url, pass in the client to use, in case you would like to re-use an existing client
      topic: 'zbtk' // (base) topic to publish messages
    }
  }
});

capEmitter.on('data', function(data, context) {
  // the raw / unparsed packet data, in case the packet was
  // parsed (e.g. due to "packet" being set in the emit
  // options), context already includes the parsed packet
  const { packet, type } = context;
});
capEmitter.on('packet', function(packet, context) {
  // parsed / decrypted in case "packet" is set in the emit
  // options and decrypted in case of any pre-configured key
  // matched to decrypt the packet contents. context includes:
  const { data, type } = context;
});

capEmitter.on('attribute', function(attr, context) {
  const {
    id, // the 2-byte ID of the attribute in the cluster (in big-endian notation)
    type, // the 2-byte type of the attribute
    value // the parsed value (string, number, Buffer, ...)
  } = attr;
  // the context includes further information about the attribute:
  const {
    data, // the raw data buffer of the packet
    packet, // the full parsed packet
    type: packetType, // the packet type
    eui, // the EUI-64 of the device this attribute was read from / written to
    addr, // the internal network address of the device
    cluster, // the ZigBee cluster ID of the attribute (in big-endian notation)
    profile, // the ZigBee cluster profile of the attribute (in big-endian notation)
    write // true in case the attribute was captured on a write packet to the device, otherwise was either a report / read attribute packet
  } = context;
});

await capEmitter.close();

import { open as openCap } from '../cap.js';

// set pre-configured keys for automatic decryption either via the
// ZBTK_CRYPTO_PKS / ZBTK_CRYPTO_WELL_KNOWN_PKS env. variables or:
// import { pk } from '../crypto.js';
// pk('D0:D1:D2:D3:D4:D5:D6:D7:D8:D9:DA:DB:DC:DD:DE:DF');

const capSession = await openCap('device-id', {
  bufferSize: 10 * 1024 * 1024, // in bytes, defaults to 10 MB
  emit: ['attribute'], // defaults to "attribute", one, multiple of: "raw_packet", "packet", "attribute"
  out: {
    log: ['packet', 'warn', 'error'], // defaults to ['warn', 'error'], true to emit what in the emit array + warn and error, or array / string similar to emit
    mqtt: { // defaults to null
      url: 'mqtt://localhost:1883', // see https://www.npmjs.com/package/mqtt#connect url
      options: { // see https://www.npmjs.com/package/mqtt#connect options
        username: 'user',
        password: 'pass'
      },
      topic: 'zbtk' // (base) topic to publish messages
    }
  }
});

# NodeJS ZigBee Toolkit / CLI (ZBTK)

[![Test](https://github.com/kristian/zbtk/actions/workflows/test.yml/badge.svg)](https://github.com/kristian/zbtk/actions/workflows/test.yml) [![Lint](https://github.com/kristian/zbtk/actions/workflows/lint.yml/badge.svg)](https://github.com/kristian/zbtk/actions/workflows/lint.yml) [![Issues](https://img.shields.io/github/issues/kristian/zbtk)](https://github.com/kristian/zbtk/issues) [![NPM Version](https://img.shields.io/npm/v/zbtk)](https://www.npmjs.com/package/zbtk)

A NodeJS based ZigBee Toolkit & Command Line Interface (CLI) for general use.

## Table of Contents

- [Installation](#installation)
- [Usage / Tools in the Toolkit](#usage--tools-in-the-toolkit)<!-- toctools -->
  * [`cap.js` Capture ](#zbtk-cap)
  * [`cluster.js` Cluster Library Name and Attributes](#zbtk-cluster)
  * [`crypto.js` Encrypt / Decrypt Frames](#zbtk-crypto)
  * [`format.js` Format ICs / EUIs / ...](#zbtk-format)
  * [`hash.js` Hash / Checksum Calculation](#zbtk-hash)
  * [`ic.js` Install Code Utilities](#zbtk-ic)
  * [`parse.js` Packet Binary Parser](#zbtk-parse)
  * [`type.js` Determine Packet Type](#zbtk-type)<!-- toctoolsend -->
- [Application Examples](#application-examples)
- [Author](#author)
- [Bugs](#bugs)
- [License](#license)

### Really?! "Yet another ZigBee Library"?

When I started exploring ZigBee, my general understanding was that ZigBee is an open standard. So finding my way into the inner workings should have been as easy as reading up on a couple of specification documents. Soon it turned out that except [a few][1], [notable][2], [exceptions][3], coherent information about the standard and especially reference implementations of its (cryptographic) algorithms was scattered far and sparse. A lot of information seems to be held back behind the "being or becoming a [member of the ZigBee alliance](https://csa-iot.org/become-member/)" paywall.

With this toolkit I wanted to provide an easy to grasp pseudo-reference (aka "as far as my understanding goes") implementation of some of the algorithms defined in the ZigBee specification / standard, mainly referencing three documents, the [ZigBee][A], [ZigBee Base Device Behavior][B] and the [ZigBee Cluster Library][C] specifications. Other helpful documents (most notably by [Silicon Labs](https://www.silabs.com/)), can be found in the [`docs`](docs/) folder.

[1]: https://github.com/osresearch/ZbPy/
[2]: https://lucidar.me/en/zigbee/autopsy-of-a-zigbee-frame/
[3]: https://github.com/andrebdo/c-crumbs/

[A]: docs/zigbee-spec.pdf
[B]: docs/zigbee-base-device-behavior-spec.pdf
[C]: docs/zigbee-cluster-library-spec.pdf

## Installation

Install globally to use ZigBee Toolkit CLI:

```bash
npm install -g zbtk
```

Or run directly with `npx` / `yarn dlx`:

```bash
# NPM
npx zbtk
# Yarn
yarn dlx zbtk
```

In case you want to use the API, add the package to your project using your package manager of choice:

```bash
# NPM
npm install zbtk
# Yarn
yarn add zbtk
```

## Usage / Tools in the Toolkit

The basic structure of this toolkit is as follows: Each file provided can be either used as a standalone NodeJS import / library and / or as a tool to use via the command line (CLI). The toolkit currently contains the following tools:

- [`cap.js`](#zbtk-cap): Packet / Attribute (to MQTT) Capture
- [`cluster.js`](#zbtk-cluster): Cluster Library Name and Attributes
- [`crypto.js`](#zbtk-crypto): Encrypt / Decrypt Packets
- [`format.js`](#zbtk-format): Format ICs / EUIs / ...
- [`hash.js`](#zbtk-hash): Hash / Checksum Calculation
- [`ic.js`](#zbtk-ic): Install Code Utilities
- [`parse.js`](#zbtk-parse): Packet Binary Parser
- [`type.js`](#zbtk-type): Determine Packet Type

All tools are exposed via the `zbtk` command line:

```bash
zbtk <tool>

Tools:
  zbtk cap [file]                  Packet / Attribute (to MQTT) Capture
  zbtk cluster <id>                Cluster Library Name and Attributes
  zbtk encrypt [data]              Encrypt Packet
  zbtk decrypt [data]              Decrypt Packet
  zbtk format <type> [data]        Format ICs / EUIs / ...
  zbtk hash [type] [data]          Hash / Checksum Calculation
  zbtk ic <action> [install-code]  Install Code Utilities
  zbtk parse [data]                Packet Binary Parser
  zbtk type [data]                 Determine Packet Type

Options:
  --help     Show help                                                                     [boolean]
  --version  Show version number                                                           [boolean]
```

### <a id='zbtk-cap'></a>[`cap.js`](cap.js) Packet / Attribute (to MQTT) Capture 

This tool is used to capture ZigBee packets and its attributes from a (P)CAP compatible capture stream or file, as produced by tools like `tcpdump` or `dumpcap`. Any compatible ZigBee Sniffer can be used as a source device for the (P)CAP stream, for instance a [Ubisys IEEE 802.15.4 Wireshark USB Stick](https://www.ubisys.de/en/products/for-zigbee-product-developers/wireshark-usb-stick/) (or any other device, that outputs a (P)CAP compatible stream, see [tested capture devices](docs/tested-capture-devices.md)). The tool can optionally parse the packet contents, decrypt them with (pre-defined) network keys and publishing the packets and / or parsed attributes of the packets via the [`EventEmitter`](https://nodejs.org/api/events.html#class-eventemitter) interface and / or via MQTT to an external event stream.

```
Any Compatible ZigBee Sniffing / Capture Device / (Network) Adapter -> (P)CAP Utility (i.e. tcpdump / dumpcap) -> ZBTK cap.js
  (-> parse [-> decrypt] (-> extract attributes))
    (-> Console Log)
    (-> EventEmitter)
    (-> MQTT)
```

The captured raw / binary packet data may be published / emitted, based on the `emit` options. Packet contents can be automatically parsed into an object model / structure. In case the content contains encrypted data, an attempt is made to decrypt the data with any pre-shared keys provided. Attributes can be extracted from `WRITE`/`READ`/`REPORT` attribute(s) packets and forwarded to the eventing interface. This last feature is especially helpful to mimic a [ZigB
ee2MQTT](https://www.zigbee2mqtt.io/)-style event stream for ZigBee networks that you don't want to replace the coordinator / bridge for. See the [application examples](#application-examples) for when this becomes useful.

#### API Usage

```js
import { process as processCap } from 'zbtk/cap';

// set pre-configured keys for automatic decryption either via the
// ZBTK_CRYPTO_PKS / ZBTK_CRYPTO_WELL_KNOWN_PKS env. variables or:
import { pk } from 'zbtk/crypto';
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
```

The returned `capEmitter` acts as a `EventEmitter`, that emits all events of the `emit` array:

```js
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
```

It emits the raw / binary packet contents as `Buffer` and / or parsed and / or decrypted packet as an `Object`. In case `attribute` is part of the `emit` option the `capEmitter` publishes all attributes captured from `WRITE`/`READ`/`REPORT` packets to:

```js
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
```

In case `out.log` is set, emits are also print to `stdout` / console. `out.log` may include different options than `emit`, e.g. set `out.log` to `data` to print out the binary data of each packet to console, while emitting the parsed attributes to the eventing interface or MQTT if the `out.mqtt` option is set. Note that the packet always gets parsed in case either `emit` or `out.log` contains `packet` or `attribute`, or in case a `filter` is set.

To close any MQTT client created when the `out.mqtt` option as set, invoke the `.close()` function:

```js
await capEmitter.close();
```

#### CLI Usage

<!--- cSpell:disable --->
```bash
zbtk cap [file]

Packet / Attribute (to MQTT) Capture

Positionals:
  file  PCAP file to read instead of STDIN                                                  [string]

Options:
  -u, --unwrap                                       Layers to unwrap to get to the WPAN packet
                                         [array] [choices: "eth", "ip4", "ip6", "tcp", "udp", "zep"]
  -e, --emit                                         Events to emit to MQTT
                           [array] [choices: "data", "packet", "attribute"] [default: ["attribute"]]
  -l, --log                                          Log outputs, defaults "info", if no output MQTT
                                                     also to "packet", --no-log to disable
         [array] [choices: false, "data", "packet", "attribute", "info", "warn", "error", "verbose"]
  -f, --filter                                       Filter packets to emit / log (whence
                                                     expression)                            [string]
      --mqtt-host, --mh                              MQTT broker host                       [string]
      --mqtt-port, --mp                              MQTT broker port       [number] [default: 1883]
      --mqtt-username, --mu, --mqtt-user             MQTT broker username                   [string]
      --mqtt-password, --mp, --mqtt-pw, --mqtt-pass  MQTT broker password                   [number]
      --mqtt-topic, --mt                             MQTT topic           [string] [default: "zbtk"]
      --help                                         Show help                             [boolean]

Examples:
  zbtk cap trace.pcap --filter 'type != \"WPAN_ACK\"  Process trace.pcap for non-WPAN packets and
  && type != \"WPAN_COMMAND\"'                        print them to console
  zbtk cap --emit attribute --mqtt-host localhost     Process packets from STDIN and emit captured
  --mqtt-user user --mqtt-pass password               attributes to an MQTT broker
```
<!--- cSpell:enable --->

To enable automatic decryption of packets, set the pre-configured keys for your network via the `ZBTK_CRYPTO_PKS` and / or `ZBTK_CRYPTO_WELL_KNOWN_PKS` environment variables.

#### Environment Variables

- See `ZBTK_CRYPTO_PKS` and `ZBTK_CRYPTO_WELL_KNOWN_PKS` of [`crypto.js`](#zbtk-crypto), to pre-configure keys for automatic packet decryption.
- `ZBTK_CAP_PASS_NO_EUI` by default `cap.js` will attempt to only emit / publish the known IEEE EUI-64 IDs of any device (often printed as a label on the device). The tool will attempt to map given network packets to the devices EUI by creating what is called an address table. In case a device is not present in the address table yet, an error is emitted. To pass the internal network address instead of the EUI set this environment variable.
- `ZBTK_FORMAT_EUI_SEPARATOR` of [`format.js`](#zbtk-format), for EUI separator style when publishing e.g. to MQTT.

### <a id='zbtk-cluster'></a>[`cluster.js`](cluster.js) Cluster Library Name and Attributes

This tool provides information about clusters of the ZigBee Cluster Library according to its [specification document][C]. It will map a given Cluster ID to a human-readable name, as well as provide information about the clusters attributes mapping the Attribute ID and its human-readable name.

#### API Usage

<!--- examples/cluster.js --->
```js
import getCluster from 'zbtk/cluster';

const cluster = getCluster(0x0001);
cluster.name === 'Power Configuration';
cluster.get(0x0000) === 'Mains Voltage';
```

#### CLI Usage

```bash
zbtk cluster <id>

Cluster Library Name and Attributes

Positionals:
  id  Cluster ID                                                                 [string] [required]

Options:
      --version                      Show version number                                   [boolean]
  -a, --attributes, --attr, --attrs  List the attributes for the given cluster             [boolean]
      --help                         Show help                                             [boolean]

Examples:
  zbtk cluster 0x0001               Get the name for the given cluster ID
  zbtk cluster 0x0002 --attributes  Get the name and attributes for the given cluster ID
```

### <a id='zbtk-crypto'></a>[`crypto.js`](crypto.js) Encrypt / Decrypt Frames

This tool encrypts and decrypts ZigBee packet contents. According to the [ZigBee Cluster Library specification][C], the payload of ZigBee Network Layer (NWK) Data frames may be encrypted using an AES-based encryption scheme. To perform encryption and decryption, a so-called Network Key is required.

The security level of a ZigBee network determines how this Network Key is determined. In some cases, a well-known key — one that is publicly available, shared, and never changing — is used for encryption and decryption. Alternatively, the key is exchanged dynamically between the ZigBee device, router, and network coordinator using a secure protocol. Multiple key exchange mechanisms exist.

In the most basic form, the well-known ZigBee transport key (also known as the "Trust Center link key" or the `ZigBeeAlliance09` key) is used to establish a secure connection, after which a randomly generated or custom transport key replaces it for all further communication. This ensures that only the initial key exchange relies on the well-known key.

For an additional layer of security, a devices Install Code can be used to generate a Temporary Link Key, which replaces the well-known transport key during the initial key exchange. This method is discussed and demonstrated in the [Application Examples](#application-examples) section.

The initialization vector (IV) for the cryptographic operation is derived from the unencrypted header information of the ZigBee packet. This includes the (extended) sender address, the frame counter, and the security control field. Additionally, ZigBee security ensures that most of the network control header is authenticated using a Message Integrity Code (MIC). This mechanism helps prevent tampering and replay attacks by verifying the authenticity of the transmitted data. 

For example take this full encrypted "Read Attributes Response" ZigBee Cluster Library network packet:

```hex
0000   48 22 00 00 47 49 1e 12 28 ef a0 05 00 2b d6 18
0010   fe ff 27 87 04 00 fa 5e 63 9d 2f 33 14 39 63 21
0020   f6 e8 2e 41 e2 4e 3a ea 20 11 51 f9 ec 56 9a
```

The 7th bit of the first two bytes (the so called frame control field `48 22`) indicate that the content is encrypted. In order to decrypt the packet we need:

- We ignore the `00 00` (source address), `47 49` (target address), `1e` (radius) and `12` (sequence number) bytes
- And take the security header starting with `28` (security control field), `ef a0 05 00` (frame counter), `2b d6 18 fe ff 27 87 04` (extended source address) and `00` (key sequence number)
- Now follows the to be encrypted content `fa 5e 63 9d 2f 33 14 39 63 21 f6 e8 2e 41 e2 4e 3a ea 20 11 51`, up until the last 4 bytes `f9 ec 56 9a` being the message integrity code (MIC)

In order to decrypt the content we need the following input parameters:

- `nk`, in this case: `52f0fe8052ebb35907daa243c95a2ff4` (previously captured, see the full [Application Examples](#application-examples) below)
- `src64`, the extended source address, so `2bd618feff278704`
- `fc`, the frame counter, so `efa00500`
- `scf`, the security control field, so `28`
- `aad`, the additional auth. data, which in this case is the whole network + security header, starting `48 22 ... 04 00`, so `4822000047491e1228efa005002bd618feff27870400`
- `data`, the to be decrypted data, so `fa5e639d2f3314396321f6e82e41e24e3aea201151`
- `mic`, the message integrity code `f9ec569a`

This, after passing it to the decrypt function / CLI, provides us with the decrypted message / cluster frame response:

```hex
0000   40 02 05 0b 04 01 01 79 08 3d 01 1c 01 00 20 9c
0010   1d 01 00 28 c3
```

The same algorithm is applied in reverse to encrypt the packet.

#### API Usage

<!--- examples/crypto.js --->
```js
import { encrypt, decrypt } from 'zbtk/crypto';

const nk = Buffer.from('52f0fe8052ebb35907daa243c95a2ff4', 'hex');
const src64 = Buffer.from('0db123feffa7db28', 'hex');
const fc = Buffer.from('148a0700', 'hex');
const scf = Buffer.from('28', 'hex');
const aad = Buffer.from('48220000777f1e2028148a07000db123feffa7db2800', 'hex');
const data = Buffer.from('4235bf415d82f5f46c205476a2e6e3d23bfa', 'hex');
const mic = Buffer.from('1d37730e', 'hex');

decrypt(data, nk, src64, fc, scf, aad, mic).equals(Buffer.from('40020102040101ef0c2112100a014029a806', 'hex'));
// use encrypt(...) with the same parameterization, to encrypt the packet again
```

In order to register pre-configured keys, i.e. well-known network keys, used in the [`parse.js`](#zbtk-parse) tool for decrypting network packets on the fly, use the `pk()` function:

<!--- examples/pks.js --->
```js
import { pks, pk } from 'zbtk/crypto';

const nk = Buffer.from('52f0fe8052ebb35907daa243c95a2ff4', 'hex');
pk(nk); // register the network key as pre-configured key
pks[0].equals(nk);
```

#### CLI Usage

##### Encryption

```bash
zbtk encrypt [data]

Encrypt Packet

Positionals:
  data  Data to encrypt                                                                     [string]

Options:
  --version                Show version number                                             [boolean]
  --network-key, --nk      Network Key (i.e. temp. Link Key)                     [string] [required]
  --ext-address, --src64   Extended IEEE Sender Address (8 bytes)                [string] [required]
  --frame-counter, --fc    Frame Counter (4 bytes)                               [string] [required]
  --sec-ctrl-field, --scf  Security Control Field (1 byte)                       [string] [required]
  --add-auth-data, --aad   Additional Authenticated Data                         [string] [required]
  --mic-length, --mic      Message Integrity Code Length                       [number] [default: 4]
  --help                   Show help                                                       [boolean]

Examples:
  zbtk encrypt --nk 52f0fe8052ebb35907daa243c95a2ff4  Encrypt the given data
  --src64 0db123feffa7db28 --fc 148a0700 --scf 28
  --aad 48220000777f1e2028148a07000db123feffa7db2800
  40020102040101ef0c2112100a014029a806
  echo -n 40020102040101ef0c2112100a014029a806 |      Decrypt the given data
  zbtk encrypt --nk 52f0fe8052ebb35907daa243c95a2ff4
  --src64 0db123feffa7db28 --fc 148a0700 --scf 28
  --aad 48220000777f1e2028148a07000db123feffa7db2800
```

##### Decryption

```bash
zbtk decrypt [data]

Decrypt Packet

Positionals:
  data  Data to decrypt                                                                     [string]

Options:
  --version                Show version number                                             [boolean]
  --network-key, --nk      Network Key (i.e. temp. Link Key)                     [string] [required]
  --ext-address, --src64   Extended IEEE Sender Address (8 bytes)                [string] [required]
  --frame-counter, --fc    Frame Counter (4 bytes)                               [string] [required]
  --sec-ctrl-field, --scf  Security Control Field (1 byte)                       [string] [required]
  --add-auth-data, --aad   Additional Authenticated Data                         [string] [required]
  --msg-int-code, --mic    Message Integrity Code Length                                    [string]
  --help                   Show help                                                       [boolean]

Examples:
  zbtk decrypt --nk 52f0fe8052ebb35907daa243c95a2ff4 --src64 0db123feffa7db28 --fc 148a0700 --scf
  28 --aad 48220000777f1e2028148a07000db123feffa7db2800 --mic 1d37730e
  4235bf415d82f5f46c205476a2e6e3d23bfa
  echo -n 4235bf415d82f5f46c205476a2e6e3d23bfa | zbtk decrypt --nk
  52f0fe8052ebb35907daa243c95a2ff4 --src64 0db123feffa7db28 --fc 148a0700 --scf 28 --aad
  48220000777f1e2028148a07000db123feffa7db2800 --mic 1d37730e
```

#### Environment Variables

- `ZBTK_CRYPTO_PKS` a comma / space separated list of pre-configured keys (i.e. link or well-known transport keys), to use for decryption for example during parsing a packet with the [`parse.js`](#zbtk-parse) tool.
- `ZBTK_CRYPTO_WELL_KNOWN_PKS` set to `1` / `true` in order to pre-populate the list of pre-configured keys with well-known transport keys, e.g. the `ZigBeeAlliance09` key or the key commonly used in uncertified devices.
- `ZBTK_CRYPTO_NO_WIRE_WORKAROUND` set to `1` / `true` to *not* apply the WireShark workaround to the security header. For some reason the security control field is not filled in correctly in the header when being captured. In order for a successful decryption it was necessary to set `ZBEE_SEC_ENC_MIC32` field to `5`. Not sure why, but WireShark does it and this was the only way I got the message to decrypt.

### <a id='zbtk-format'></a>[`format.js`](format.js) Format ICs / EUIs / ...

This tool provides different ZigBee specific formatting functions, e.g. for specification compliant formatting of a Install Code or EUI.

#### API Usage

<!--- examples/format.js --->
```js
import { ic, eui } from 'zbtk/format';

ic(Buffer.from('83fed3407a939723a5c639b26916d505c3b5', 'hex')) === '83FE D340 7A93 9723 A5C6 39B2 6916 D505 C3B5';
eui(Buffer.from('01000000006f0d00', 'hex')) === '00:0D:6F:00:00:00:00:01';
```

#### CLI Usage

```bash
zbtk format <type> [data]

Format ICs / EUIs / ...

Positionals:
  type  Type                                              [string] [required] [choices: "ic", "eui"]
  data  Data to format                                                                      [string]

Options:
  --version  Show version number                                                           [boolean]
  --help     Show help                                                                     [boolean]

Examples:
  zbtk format ic                                      Format the given data as an Install Code
  83fed3407a939723a5c639b26916d505c3b5
  zbtk format eui 01000000006f0d00                    Format the given data as an EUI
```

#### Environment Variables

- `ZBTK_FORMAT_EUI_SEPARATOR` the separator used to format EUIs, defaults to `:` (as for MAC-addresses) e.g. `00:0D:6F:00:00:00:00:01`, may be changed to `-`, e.g. `00-0D-6F-00-00-00-00-01` as some manufacturers of ZigBee devices denote the EUIs of their devices separated with `-` instead.

### <a id='zbtk-hash'></a>[`hash.js`](hash.js) Hash / Checksum Calculation

This tool calculates ZigBee specific hash / checksum values for a given input. Following types of hashes / checksums are supported:

- `crc`: CRC-16 as used in the ZigBee Install Code validation procedure, following section 10.1.1 of the [ZigBee Base Device Behavior][B] specification, the CRC-16 uses the CCITT CRC1775 standard polynomial: 𝑥<sup>16</sup>+𝑥<sup>12</sup>+𝑥<sup>5</sup>+1.
- `mmo`: The Matyas-Meyer-Oseas hash function, as used for example when generating a Link Key based on a given Install Code. In order to calculate the Link Key, prefer using the `link` function of the [`ic.js`](#zbtk-ic) tool, which will internally call the `mmo` function, as it also validates the Install Codes checksum, before generating a wrong hash. The MMO hash is used as a temporary key to encrypt message traffic during the initial exchange to a Transport Key.
- `key`: The function to generate a hashed-key as outlined by B.1.4 of the [ZigBee Specification][A], and in FIPS Publication 198. The key hash function is used, to generate the cryptographic key used during the initial exchange when using a Link Key instead of a well-known Trust Center Key.

#### API Usage

<!--- examples/hash.js --->
```js
import { crc, mmo, key } from 'zbtk/hash';

crc(Buffer.from('83fed3407a939723a5c639b26916d505', 'hex')).equals(Buffer.from('c3b5', 'hex'));
mmo(Buffer.from('83fed3407a939723a5c639b26916d505c3b5', 'hex')).equals(Buffer.from('66b6900981e1ee3ca4206b6b861c02bb', 'hex'));
key(Buffer.from('66b6900981e1ee3ca4206b6b861c02bb', 'hex')).equals(Buffer.from('364478502081de79cf903260a0c09d45', 'hex'));
```

#### CLI Usage

<!--- cSpell:disable --->
```bash
zbtk hash [type] [data]

Hash / Checksum Calculation

Positionals:
  type  Type of hash / checksum to calculate                 [string] [choices: "crc", "mmo", "key"]
  data  Data to calculate hash / checksum for                                               [string]

Options:
      --version  Show version number                                                       [boolean]
  -i, --input    Input nonce for key-based MMO hash                                         [number]
      --help     Show help                                                                 [boolean]

Examples:
  zbtk crc 83fed3407a939723a5c639b26916d505           Calculate the CRC-16 checksum for the given
                                                      data
  zbtk mmo 83fed3407a939723a5c639b26916d505c3b5       Calculate the Matyas-Meyer-Oseas (MMO) Hash of
                                                      the given data
  zbtk key 66b6900981e1ee3ca4206b6b861c02bb --input   Calculate a key-based MMO hash, with the given
  0                                                   input nonce
  echo -n 83fed3407a939723a5c639b26916d505 | zbtk     Use the non-streamed standard input to
  crc                                                 calculate the CRC-16
```
<!--- cSpell:enable --->

### <a id='zbtk-ic'></a>[`ic.js`](ic.js) Install Code Utilities

This tool provides a collection of different utility functions in regards to the ZigBee Install Code. It includes, validation / checksum calculation, as well as formatting and generation of a Link Key based on the Install Code. See the [Application Examples](#application-examples) section, on how to use a Link Key generated from a Install Code, in order to capture packets from an encrypted ZigBee network.

#### API Usage

<!--- examples/ic.js --->
```js
import { validate, checksum, format, link } from 'zbtk/ic';

validate(Buffer.from('83fed3407a939723a5c639b26916d505c3b5', 'hex')) === true;
checksum(Buffer.from('83fed3407a939723a5c639b26916d505', 'hex'), false).equals(Buffer.from('5c3b5', 'hex'));
format(Buffer.from('83fed3407a939723a5c639b26916d505c3b5', 'hex')) === '83FE D340 7A93 9723 A5C6 39B2 6916 D505 C3B5';
link(Buffer.from('83fed3407a939723a5c639b26916d505c3b5', 'hex')).equals(Buffer.from('66b6900981e1ee3ca4206b6b861c02bb', 'hex'));
```

#### CLI Usage

<!--- cSpell:disable --->
```bash
zbtk ic <action> [install-code]

Install Code Utilities

Positionals:
  action            Action to perform
                             [string] [required] [choices: "validate", "checksum", "format", "link"]
  install-code, ic  Install Code to process                                                 [string]

Options:
  --version  Show version number                                                           [boolean]
  --help     Show help                                                                     [boolean]

Examples:
  zbtk ic validate                                    Validate the given Install Code
  83fed3407a939723a5c639b26916d505c3b5
  zbtk ic checksum 83fed3407a939723a5c639b26916d505   Calculate the CRC checksum for the given
                                                      Install Code
  zbtk ic format                                      Format the given Install Code
  83fed3407a939723a5c639b26916d505c3b5
  zbtk ic link 83fed3407a939723a5c639b26916d505c3b5   Calculate the Link Key for the given Install
                                                      Code
```
<!--- cSpell:enable --->

### <a id='zbtk-parse'></a>[`parse.js`](parse.js) Packet Binary Parser

This tool provides a ZigBee binary packet parser (and *soon™* some encoder) functionality based on the awesome [`binary-parser`](https://github.com/keichi/binary-parser) library by [Keichi Takahashi](https://github.com/keichi). It converts a raw ZigBee packet into a object structure, whilst converting its properties, decrypting the packet if needed and parsing any attributes of the packet. The parsing format was inspired by the Wireshark structure. The tool supports parsing / encoding encapsulated:

- ZigBee Encapsulation Protocol (`ZEP`) packets
- Wireless Personal Area Network (`WPAN`) packets
- ZigBee Network Layer (`ZBEE_NWK`) packets
- ZigBee Application Support Sub-layer (`ZBEE_APS`) packets
- ZigBee Cluster Library (`ZBEE_ZCL`) packets
- ZigBee Device Profile (`ZBEE_ZDP`) packets

The `parse.js` tool will automatically attempt decrypting encrypted ZigBee packets, in case keys have been pre-configured via the `ZBTK_CRYPTO_PKS` and `ZBTK_CRYPTO_WELL_KNOWN_PKS` environment variables or the [`crypto.js`](#zbtk-crypto) API. When parsing encrypted packets, `parse.js` will try to decrypt the packet with any of the provided pre-configured keys and validate the decryption using the decryption signature / message integrity code (MIC). In case no keys are pre-configured or no key leads to a successful decryption of the packet the unencrypted data is left in the packet, or in case the `ZBTK_PARSE_FAIL_DECRYPT` environment variable is set, fails the parsing.

> [!NOTE]
> As per ZigBee specification parsed binary values / packet contents, such as `Buffer`, are always in little-endian encoding / notation. Other tools, such as [`cluster.js`](#zbtk-cluster) or whenever communicating data to an end-user, e.g. during [`cap.js`](#zbtk-cap) packet capture, values are converted into big-endian notation.

> [!IMPORTANT]
> Currently, the packet parser *does not* claim complete specification compliance! Meaning that most parser features have been developed on a 'come as you go' basis, not based on the extensive ZigBee specification documentation. Depending on the type / contents of a packet, this may results in parsing / malformed packet errors. Parsed data can be easily compared using Wireshark. In case of any discrepancy / error, please raise an issue or pull request, including the raw `ZEP` packet content and to compare the parsed results. Please note that in case your packet is encrypted with a Network Key, you will need to provide the Network Key to the processor of the ticket, or provide information how to capture a similar packet / reproduce the issue in the local network of the processors network. We strongly **do not** recommend sharing your Network Key openly, as it would allow anyone to decrypt your networks traffic. Only provide your Network Key to people you trust.

#### API Usage

<!--- cSpell:disable --->
<!--- examples/parse.js --->
```js
import { pk } from 'zbtk/crypto';
import { parse } from 'zbtk/parse';

pk(Buffer.from('52f0fe8052ebb35907daa243c95a2ff4', 'hex')); // register the network key as pre-configured key for automatic decryption of the parsed packets

`${parse(Buffer.from('4558020113fffe0029d84f48995f78359c000a91aa000000000000000000000502003ffecb', 'hex'), 'zep')}` === '{"protocol_id":"EX","version":2,"type":1,"channel_id":19,"device_id":65534,"lqi_mode":0,"lqi":41,"time":{"$hex":"d84f48995f78359c"},"seqno":692650,"length":5,"wpan":{"fcf":{"$hex":"0200"},"fc":{"reserved":false,"pan_id_compression":false,"ack_request":false,"pending":false,"security":false,"type":2,"src_addr_mode":0,"version":0,"dst_addr_mode":0,"ie_present":false,"seqno_suppression":false},"seq_no":63,"fcs":{"$hex":"fecb"}}}';
```
<!--- cSpell:enable --->

#### CLI Usage

<!--- cSpell:disable --->
```bash
zbtk parse [data]

Packet Binary Parser

Positionals:
  data  Data to parse                                                                       [string]

Options:
      --version  Show version number                                                       [boolean]
  -t, --type     Type of packet to parse
           [string] [choices: "zbee_zdp", "zbee_zcl", "zbee_aps_cmd", "zbee_aps_secure", "zbee_aps",
  "zbee_nwk_cmd", "zbee_cmd", "zbee_nwk_secure", "zbee_nwk", "zbee_beacon", "wpan", "zep"] [default:
                                                                                             "wpan"]
      --help     Show help                                                                 [boolean]

Examples:
  zbtk parse --type zep 4558020113fffe0029d84f48995f  Parse the given data as a ZigBee Encapsulation
  78359c000a91aa000000000000000000000502003ffecb      Protocol (ZEP) packet
  echo -n 4558020113fffe0029d84f48995f78359c000a91aa  Parse the given data from stdin as a ZigBee
  000000000000000000000502003ffecb | zbtk parse       Encapsulation Protocol (ZEP) packet
  --type zep
```
<!--- cSpell:enable --->

#### Environment Variables

- See `ZBTK_CRYPTO_PKS` and `ZBTK_CRYPTO_WELL_KNOWN_PKS` of [`crypto.js`](#zbtk-crypto), to pre-configure keys for automatic packet decryption.
- Set `ZBTK_PARSE_FAIL_DECRYPT` to raise an error in case an encrypted packet cannot be decrypted with the provided (or missing) pre-configured keys, instead of just logging a warning and keeping the raw data `Buffer` in the packet.
- Set `ZBTK_PARSE_SKIP_FCS_CHECK` to skip the FCS / CRC validation for IEEE 802.15.4 Low-Rate Wireless PAN (WPAN) packets. This is required, as in some cases adapters will validate the FCS themselves and replace it with other information, such as TI CC24xx-format metadata, RSSI / LQI information. In such cases `ZBTK_PARSE_SKIP_FCS_CHECK` should be set and checking the FCS can be safely skipped.
- Set `ZBTK_PARSE_KEEP_TEMP` to keep temporary / temporal values used for parsing the packet. This is helpful when debugging the packet parsing. Temporary fields are prefixed with a `$` dollar sign and are removed by default before the packet is returned from parsing.

### <a id='zbtk-type'></a>[`type.js`](type.js) Determine Packet Type

This tool is a helper to determine the packet type of a parsed or raw ZigBee packet. The interface accepts the same (parsed) packet as the [`parse.js`](#zbtk-parse) tool and returns the type of the packet as string. This is especially helpful to filter for specific packet types. For example during [`cap.js`](#zbtk-cap), ZigBee networks are quite noisy due to a lot of `WPAN_ACK` / `WPAN_COMMAND` packages, that are mostly irrelevant when analyzing the network traffic. Determining the type of the packet and filtering the captured package traffic, helps to narrow down the traffic.

#### API Usage

<!--- examples/type.js --->
```js
import getPacketType from 'zbtk/type';

getPacketType(Buffer.from('4558020113fffe0029d84f48995f78359c000a91aa000000000000000000000502003ffecb', 'hex'), 'zep') === 'WPAN_ACK';
```

#### CLI Usage

<!--- cSpell:disable --->
```bash
zbtk type [data]

Determine Packet Type

Positionals:
  data  Packet to determine the type for                                                    [string]

Options:
  --version  Show version number                                                           [boolean]
  --type     Type of packet to determine the type for
              [string] [choices: "zbee_zcl_cmd", "zbee_zcl", "zbee_zdp", "zbee_aps_cmd", "zbee_aps",
                             "zbee_nwk_cmd", "zbee_nwk", "wpan_cmd", "wpan", "zep"] [default: "zep"]
  --help     Show help                                                                     [boolean]

Examples:
  zbtk type 4558020113fffe0029d84f48995f78359c000a91  Determine the type of ZigBee Encapsulation
  aa000000000000000000000502003ffecb                  Protocol (ZEP) packet
  echo -n 4558020113fffe0029d84f48995f78359c000a91aa  Determine the type of a ZigBee Encapsulation
  000000000000000000000502003ffecb | zbtk type        Protocol (ZEP) packet from stdin
```
<!--- cSpell:enable --->

## Application Examples

This section walks through some end-to-end use-cases of the ZigBee Toolkit by example. As a prerequisite please follow the [installation instructions](#installation) to install the ZigBee Toolkit.

### Capturing Attributes of Devices in an encrypted ZigBee Network

This example guides you through the process of capturing / tracing attributes of ZigBee devices in an existing and encrypted ZigBee network. This is useful in case you do not have access to the the ZigBee bridge / coordinator, for example because it is a proprietary / manufacturer specific bridge, or you are not willing to replace an existing ZigBee bridge for an open-source implementation like [ZigBee2MQTT](https://www.zigbee2mqtt.io/). The upcoming example focusses on capturing attributes from thermostats (so called "TRVs") from an existing Viessmann ViCare ZigBee network. However the same mechanism / approach that is described here in this guide, should be applicable to any other ZigBee network, that you want to capture packets from as well. This this guide shows you how to:

- Monitor / capture an existing encrypted ZigBee network
- Extract attributes from packets sent to / from the devices (like TRVs)
- Feed those attributes into my MQTT broker (e.g. for further processing in Home Assistant)
- All whilst staying local network / not requiring any internet connectivity
- All that without interrupting the existing ZigBee networks internal workings / exchanging the broker

Note that the ZigBee Toolkit is not affiliated with Viessmann (Group GmbH & Co. KG), ViCare, its products, or subsidiaries in any way, shape, or form. However, they do not provide any local API to access the TRVs data. Their cloud-based API requires a monthly subscription and an internet connection to work. Thus it became the leading use-case for me, that facilitated the development of the ZigBee Toolkit and an good example show-case for this guide as well.

There are many instructions online, on how to sniff into an existing ZigBee network. For example [this excellent guide](https://www.zigbee2mqtt.io/advanced/zigbee/04_sniff_zigbee_traffic.html) from the ZigBee2MQTT project. Reading through that guide, to get a basic understanding about sniffing, is definitely helpful, but the instructions of this guide will step-by-step explain the process as well.

First you will have to decide for the sniffing hardware to use. Many ZigBee USB-Sticks and / or network adapters will either support sniffing out of the box, or provide specific firmware, that can be flashed onto the device, to enable sniffing. Best refer to the [ZigBee2MQTT guide](https://www.zigbee2mqtt.io/advanced/zigbee/04_sniff_zigbee_traffic.html) and the [tested capture devices](docs/tested-capture-devices.md) list, for an overview.

In my case I started with a "ready-to-use" solution, like the [Wireshark USB-Stick by Ubisys](https://www.ubisys.de/en/products/for-zigbee-product-developers/wireshark-usb-stick/), but ended up using the SMLIGHT SLZB-06M ethernet dongle instead, which struck me as the best balance between price to performance. I also successfully tested the toolkit with a (cheap) CC2531 adapter. Other capture sticks / adapters should work as well, as long as there is an interface / utility to generate a (P)CAP compatible stream, that can be piped into the ZigBee Toolkit.

#### 1. Find Network Channel

First step is to find out, on which channel data is sent. ZigBee sends data on multiple channels, channel 11-26 to be exact. We have to determine the capture channel, before we can start sniffing for packets. In order to change the channel, refer to the manual of your capture device. Below you will find some examples for setting the channel on different capture devices.

Finding the right channel is more or less trial & error: Set a channel, start the packet capture and see if there is any traffic. Wait for couple of seconds, if you don't see data, rinse & repeat with the next channel. If you hit the right channel, you should see packet data.

<details>
  <summary><b>Ubisys IEEE 802.15.4 Wireshark USB Stick</b></summary>

Make sure you followed the [set-up instructions](https://www.ubisys.de/wp-content/uploads/ubisys-ieee802154-wireshark-manual.pdf) for the Ubisys stick, from Ubisys website. Afterwards to set a channel on Linux, use the shell script Ubisys provides you with:

```bash
sudo ./ieee802154_options.sh -c 19
```

On Windows setting the channel is baked into the driver, to set it you can use a an elevated PowerShell:

```ps
Set-NetAdapterAdvancedProperty -Name "ubisys Wireshark" -DisplayName "IEEE 802.15.4 Channel" -DisplayValue "19"
```

Continuing on Linux, set the interface `up` and check if any data is received:

```bash
sudo ip link set dev enx001fee00295e up
sudo tcpdump -n -i enx001fee00295e -vvv -s 0 'udp port 17754'
```

You either will see no data at all, so switch channels, or you will see data from all channels and `tcpdump` will show you a message like `[...] ZEPv2 Type 1, Channel ID 19 [...]`, so the right channel is channel 19.
</details>
<details>
  <summary><b>Generic CC2531 Dongle w/ TI Sniffer Firmware</b></summary>

A CC2531 dongle with TI sniffer firmware does not expose a network interface, like e.g. the Ubisys stick does. Capturing happens through a tool, that talks to the USB device directly. Supposedly `dumpcap` can talk to `libusb` to do that, however we would recommend [`whsniff`](https://github.com/homewsn/whsniff), as we can and will use it later on to pipe (P)CAP data to the ZigBee Toolkit `cap` tool. Again check channel by channel and see if you see data flowing:

```bash
sudo whsniff -c 19 | tcpdump -vvv -r -
```
</details> 
<details>
  <summary><b>SMLIGHT SLZB-06M Ethernet Dongle</b></summary>

For SMLIGHT, we could make use of the `ember-zli`, for a detailed instructions visit the [`ember-zli` Wiki](https://github.com/Nerivec/ember-zli/wiki) and also check out their [specific guide on sniffing](https://github.com/Nerivec/ember-zli/wiki/Sniff). However as the ZigBee Toolkit will require a (P)CAP output on standard out (stdout) and the Ember ZLI provides no real CLI, we recommend to use [`ember-sniff`](https://github.com/kristian/ember-sniff), another tool, based on `ember-zli` just used for sniffing / outputting PCAP:

```bash
npm install -g ember-sniff
```

Connect the SMLIGHT dongle (or any other compatible EmberZNet or HUSBZB-1 adapter) via ethernet or USB. We will use ethernet here in this example. Again connect to your dongle and repeat the process until you found the channel sending data:

```bash
ember-sniff -p tcp://192.168.1.42:6638 -c 19 | tcpdump -vvv -r -
```
</details> 

In my case the Viessmann network sent data on channel 19.

#### 2. Capturing the Transport Key

After you have found the right channel to capture data on, your next task is to capture the so called "Transport Key" of your network. The Transport Key is used by ZigBee to encrypt your networks data. You can capture a Transport Key every time a new device joins your network. This means in order to capture a Transport Key you will need either a new / spare device that can join your ZigBee network, or you will have to remove any of your existing TRVs and add it again in the next step.

In order to not leave the traffic that contains the Transport Key unencrypted, by default ZigBee will encrypt the Transport Key data with a well-known pre-configured key, the so called "Trust Center Link Key". This default key, used by most ZigBee networks, is called `ZigBeeAlliance09`. However there a other, manufacturer specific, link keys out there. In case of the ZigBee Toolkit you can set the `ZBTK_CRYPTO_WELL_KNOWN_PKS` environment variable, which will assume traffic is with the `ZigBeeAlliance09` key and start the capture.

Please refer to the [tested capture devices](docs/tested-capture-devices.md) list, to find the command to start packet capture for your device with the ZigBee Toolkit. In our example, we will continue to use an SMLight / EmberZNet and HUSBZB-1 adapters. By replacing the program that pipes in the (P)CAP data, as well as the `-u` (unwrap) option, with the settings specific for your device, the following examples should work for all tested devices in the same way:

```bash
export ZBTK_CRYPTO_WELL_KNOWN_PKS=1
ember-sniff -p tcp://192.168.1.42:6638 -c 19 | zbtk cap --no-unrap
```

As said, ZigBee supports multiple types of secure key exchange. The default is the so called "well-known" pre-shared key method, where the initial ZigBee traffic (that is used to exchange a so called "Transport Key") is sent encrypted with a well known, aka the `ZigBeeAlliance09` key: `5A:69:67:42:65:65:41:6C:6C:69:61:6E:63:65:30:39`, as described above. So it will be enough to trust this pre-shared key and wait for any new device to join the network, which will then provide you access to your transport key.

In case of the Viessmann however, they chose another another ("more safe") way of securing the network. It is protected with a so called "Link Key" that is based on the "Install Code" of the device that is about to join the network. So you will only be able to capture encrypted packages, even if you try to have a device join the network. In order to be able to capture a Transport Key in this case, you first have to populate the so called "Link Key", that will be used to encrypt the traffic instead of the well-known key. The Link Key is based on the so called "Install Code" of the device that you are trying to add to the network. The Install Code is a 18 byte hexadecimal number sequence, mostly in tuples of two bytes separated by spaces, that you should find on the label of the device. So you will have to

```text
EE91 7C25 E941 23C2 27B9 3F4D 50A0 C34F 373D
```

Sometimes your device will have a QR code printed on it. If you scan the QR code, you should find the same Install Code, or "IC" in short. In case of the Viessmann TRVs the QR code decoded to:

<!--- cSpell:disable --->
```text
11ZEUID:28DBA7FFFE23B07D$ZBIC:EE917C25E94123C227B93F4D50A0C34F373D$
```
<!--- cSpell:enable --->

Starting with `ZBIC:` you can see the Install Code. In order to now calculate the Link Key, we have to calculate the so called Matyas-Meyer-Oseas hash. We can use the [`ic.js`](#zbtk-ic) tool of the ZigBee Toolkit, that will also validate the checksum of the Install Code, so we didn't do any mistake when copying the number:

```text
zbtk ic link EE917C25E94123C227B93F4D50A0C34F373D
```

The command will output the Link Key, used to encrypt the Transport Key exchange. E.g.:

```text
4c23a848a76f432113510a301c5fdfd2
```

Let's populate the Link Key to use, instead of the well-known `ZigBeeAlliance09` trust center key, and start capturing for attributes:

```bash
export ZBTK_CRYPTO_PKS=4c23a848a76f432113510a301c5fdfd2
ember-sniff -p tcp://192.168.1.42:6638 -c 19 | zbtk cap -l attribute
```

Depending of how much traffic is in your network, you should soon start seeing some "Packet encrypted" messages in the console:

```bash
Packet encrypted / decryption failed or not attempted
Set or check ZBTK_CRYPTO_(WELL_KNOWN_)PKS environment variable(s) or capture Transport Key
Packet encrypted / decryption failed or not attempted
...
```

Now have the device, that you calculated the Link Key for join the network. If you performed the right steps, you should soon see a:

```bash
------------------------------------------------------------

Captured Transport Key 52f0fe8052ebb35907daa243c95a2ff4

Key was automatically added to pre-configured key list

------------------------------------------------------------
```

Log message, followed by the `Packet encrypted / decryption failed or not attempted` messages disappear. Congratulations, you are now successfully sniffing your ZigBee network traffic. Soon you should start seeing some attributes reported to console as well:

```bash
Thermostat (0x0201)/Occupied Heating Setpoint (0x0012): 2150 (read from 28:DB:A7:FF:FE:23:B0:7D)
Thermostat (0x0201)/Local Temperature (0x0000): 1797 (read from 28:DB:A7:FF:FE:23:04:4F)
...
```

Take good note of your transport key, as this is the key you will have to expose to the ZigBee Toolkit, for any future capture session:

```bash
export ZBTK_CRYPTO_PKS=52f0fe8052ebb35907daa243c95a2ff4
```

#### 3. Capture Attribute Data to MQTT

As a last step, lets set-up automatically capturing attributes to your local MQTT broker. We can use the same [`cap.js`](#zbtk-cap) tool command to do so (don't forget to pre-publish your captured transport key, otherwise you won't be able to record any attributes):

```bash
ember-sniff -p tcp://192.168.1.42:6638 -c 19 | zbtk cap --mqtt-host localhost --mqtt-user mqtt --mqtt-pass abcdefg
```

Please note that by specifying the MQTT parameters, the [`cap.js`](#zbtk-cap) tool will attempt to emit all attributes to MQTT instead of to the console. In case you would like to also log the attributes to console as before, use the following command instead:

```bash
ember-sniff -p tcp://192.168.1.42:6638 -c 19 | zbtk cap --mqtt-host localhost --mqtt-user mqtt --mqtt-pass abcdefg --log attribute
```

Check your MQTT broker, you should start seeing attributes of your network being populated.

## Author

ZigBee Toolkit for Node.js by [Kristian Kraljić](https://kra.lc/).

## Bugs

Please file any questions / issues [on Github](https://github.com/kristian/zbtk/issues).

Any ideas / comments, or just want to talk? Feel free to [start a discussion](https://github.com/kristian/zbtk/discussions).

## License

This library is licensed under the [Apache 2.0](LICENSE) license.

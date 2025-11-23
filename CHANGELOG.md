# Changelog

This file documents all *major & minor* releases. For revisions, please consult the [commit history](https://github.com/kristian/zbtk/commits/main).

## [2.1] - 2025-11-23

Check IEEE 802.15.4 Low-Rate Wireless PAN (WPAN) FCS for packets that are not in a ZigBee Encapsulation Protocol wrapper.

## [2.0] - 2025-11-23

**Breaking Change:** Drop support for Node.js 18. Minimum Node.js version is 20 now.

**Breaking Change:** Remove `cap` binary + dependency. The `cap.js` tool no longer relies on capturing own data via a network interface, but instead handles any (P)CAP data piped into standard input (stdin), or a PCAP file. This enables `cap.js` to work with any kind of device using external utilities, capturing data into PCAP, such as `tcpdump` for network adapters, like the Ubisys capture stick, `whsniff` for CC2531 dongles, or `ember-sniff` for EmberZNet and HUSBZB-1 adapters, like the SMLIGHT SLZB-06M dongle. All devices have been tested and added to the [tested capture devices list](docs/tested-capture-devices.md). To reflect this change in the API the `cap.js` `open(...)` function has been renamed to `process(...)` instead.

The ZigBee Encapsulation Protocol (ZEP) is no longer the default protocol for `parse.js` and `type.js` but IEEE 802.15.4 Low-Rate Wireless PAN (WPAN) packets are, as some devices capture data not as ZEP but WPAN, so "WPAN" became the default that also `cap.js` deals with. A new option `unwrapLayers` has been added to `cap.js`, so any streamed in packet can be unwrapped to the underlying WPAN to parse.

Fix issue in `parse.js` parsing WPAN packets without a ZEP wrapper. Bump dependencies.

## [1.3] - 2025-02-28

Add `bufferFormat` option to `cap.js` tool.

## [1.2] - 2025-02-18

Switch from `process.stdout` to `console.log` for better readability on Unix-based operating systems.

## [1.1] - 2025-02-17

Fixed events in `cap.js` tool, renamed `raw_packet` event to `data`.

## [1.0] - 2025-02-16

### Initial Release

Tools included:

- `cap.js` Packet capture
- `cluster.js` Cluster and attribute information
- `crypto.js` Encrypt / decrypt packets
- `format.js` Format EUI / Install Code / ...
- `crc.js` Hash / Checksum Calculation
- `ic.js` Install Code helpers, checksum, etc.
- `parse.js` Packet parser (preparation for encode)
- `type.js` Determine type of packet

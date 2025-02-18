# Changelog

This file documents all *major & minor* releases. For revisions, please consult the [commit history](https://github.com/kristian/zbtk/commits/main).

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

import getPacketType, { types } from '../type.js';

getPacketType(Buffer.from('4558020113fffe0029d84f48995f78359c000a91aa000000000000000000000502003ffecb', 'hex'), 'zep') === 'WPAN_ACK';

const uint16 = types.data[0x21];
uint16.encode(0x1234).toString('hex') === '3412';
uint16.decode(Buffer.from('3412', 'hex')) === 0x1234;

import getPacketType from '../type.js';

getPacketType(Buffer.from('4558020113fffe0029d84f48995f78359c000a91aa000000000000000000000502003ffecb', 'hex'), 'zep') === 'WPAN_ACK';

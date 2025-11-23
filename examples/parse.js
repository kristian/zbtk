import { pk } from '../crypto.js';
import { parse } from '../parse.js';

pk(Buffer.from('52f0fe8052ebb35907daa243c95a2ff4', 'hex')); // register the network key as pre-configured key for automatic decryption of the parsed packets

`${parse(Buffer.from('4558020113fffe0029d84f48995f78359c000a91aa000000000000000000000502003ffecb', 'hex'), 'zep')}` === '{"protocol_id":"EX","version":2,"type":1,"channel_id":19,"device_id":65534,"lqi_mode":0,"lqi":41,"time":{"$hex":"d84f48995f78359c"},"seqno":692650,"length":5,"wpan":{"fcf":{"$hex":"0200"},"fc":{"reserved":false,"pan_id_compression":false,"ack_request":false,"pending":false,"security":false,"type":2,"src_addr_mode":0,"version":0,"dst_addr_mode":0,"ie_present":false,"seqno_suppression":false},"seq_no":63,"ti_cc24xx_metadata":{"$hex":"fecb"}}}';

import { crc, mmo, key } from '../hash.js';

crc(Buffer.from('83fed3407a939723a5c639b26916d505', 'hex')).equals(Buffer.from('c3b5', 'hex'));
mmo(Buffer.from('83fed3407a939723a5c639b26916d505c3b5', 'hex')).equals(Buffer.from('66b6900981e1ee3ca4206b6b861c02bb', 'hex'));
key(Buffer.from('66b6900981e1ee3ca4206b6b861c02bb', 'hex')).equals(Buffer.from('364478502081de79cf903260a0c09d45', 'hex'));

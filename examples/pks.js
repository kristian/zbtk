import { pks, pk } from '../crypto.js';

const nk = Buffer.from('52f0fe8052ebb35907daa243c95a2ff4', 'hex');
pk(nk); // register the network key as pre-configured key
pks[0].equals(nk);

import { encrypt, decrypt } from '../crypto.js';

const nk = Buffer.from('52f0fe8052ebb35907daa243c95a2ff4', 'hex');
const src64 = Buffer.from('0db123feffa7db28', 'hex');
const fc = Buffer.from('148a0700', 'hex');
const scf = Buffer.from('28', 'hex');
const aad = Buffer.from('48220000777f1e2028148a07000db123feffa7db2800', 'hex');
const data = Buffer.from('4235bf415d82f5f46c205476a2e6e3d23bfa', 'hex');
const mic = Buffer.from('1d37730e', 'hex');

decrypt(data, nk, src64, fc, scf, aad, mic).equals(Buffer.from('40020102040101ef0c2112100a014029a806', 'hex'));
// use encrypt(...) with the same parameterization, to encrypt the packet again

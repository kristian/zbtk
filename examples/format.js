import { ic, eui } from '../format.js';

ic(Buffer.from('83fed3407a939723a5c639b26916d505c3b5', 'hex')) === '83FE D340 7A93 9723 A5C6 39B2 6916 D505 C3B5';
eui(Buffer.from('01000000006f0d00', 'hex')) === '00:0D:6F:00:00:00:00:01';

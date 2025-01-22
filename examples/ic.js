import { validate, checksum, format, link } from '../ic.js';

validate(Buffer.from('83fed3407a939723a5c639b26916d505c3b5', 'hex')) === true;
checksum(Buffer.from('83fed3407a939723a5c639b26916d505', 'hex'), false).equals(Buffer.from('5c3b5', 'hex'));
format(Buffer.from('83fed3407a939723a5c639b26916d505c3b5', 'hex')) === '83FE D340 7A93 9723 A5C6 39B2 6916 D505 C3B5';
link(Buffer.from('83fed3407a939723a5c639b26916d505c3b5', 'hex')).equals(Buffer.from('66b6900981e1ee3ca4206b6b861c02bb', 'hex'));

import getCluster from '../cluster.js';

const cluster = getCluster(0x0001);
cluster.name === 'Power Configuration';
cluster.get(0x0000) === 'Mains Voltage';

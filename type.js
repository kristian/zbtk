import { Buffer } from 'node:buffer';

import { parse as parsePacket } from './parse.js';

const types = {};

types.zbee_zcl_cmd = packet => {
  switch (packet?.id[0]) {
    case 0x00:
      return 'ZCL_CMD_READ_ATTR';
    case 0x01:
      return 'ZCL_CMD_READ_ATTR_RSP';
    case 0x02:
      return 'ZCL_CMD_WRITE_ATTR';
    case 0x03:
      return 'ZCL_CMD_WRITE_ATTR_UNDIVIDED';
    case 0x04:
      return 'ZCL_CMD_WRITE_ATTR_RSP';
    case 0x05:
      return 'ZCL_CMD_WRITE_ATTR_NO_RSP';
    case 0x06:
      return 'ZCL_CMD_CONFIG_REPORT';
    case 0x07:
      return 'ZCL_CMD_CONFIG_REPORT_RSP';
    case 0x08:
      return 'ZCL_CMD_READ_REPORT_CONFIG';
    case 0x09:
      return 'ZCL_CMD_READ_REPORT_CONFIG_RSP';
    case 0x0a:
      return 'ZCL_CMD_REPORT_ATTR';
    case 0x0b:
      return 'ZCL_CMD_DEFAULT_RSP';
    case 0x0c:
      return 'ZCL_CMD_DISCOVER_ATTR';
    case 0x0d:
      return 'ZCL_CMD_DISCOVER_ATTR_RSP';
    case 0x0e:
      return 'ZCL_CMD_READ_ATTR_STRUCT';
    case 0x0f:
      return 'ZCL_CMD_WRITE_ATTR_STRUCT';
    case 0x10:
      return 'ZCL_CMD_WRITE_ATTR_STRUCT_RSP';
    case 0x11:
      return 'ZCL_CMD_DISCOVER_CMDS_REC';
    case 0x12:
      return 'ZCL_CMD_DISCOVER_CMDS_REC_RSP';
    case 0x13:
      return 'ZCL_CMD_DISCOVER_CMDS_GEN';
    case 0x14:
      return 'ZCL_CMD_DISCOVER_CMDS_GEN_RSP';
    case 0x15:
      return 'ZCL_CMD_DISCOVER_ATTR_EXTENDED';
    case 0x16:
      return 'ZCL_CMD_DISCOVER_ATTR_EXTENDED_RSP';
    default:
      return 'ZCL_CMD_UNKNOWN';
  }
};

types.zbee_zcl = packet => {
  switch (packet?.fc.type) {
    case 0x0:
      return types.zbee_zcl_cmd(packet.cmd);
    case 0x1:
      return 'ZCL_ACK';
    case 0x2:
      return 'ZCL_CLUSTER_SPECIFIC';
    case 0x3:
      return 'ZCL_PROFILE_WIDE';
    default:
      return 'ZCL_UNKNOWN';
  }
};

types.zbee_zdp = (packet, cluster) => {
  if (!Buffer.isBuffer(cluster)) {
    return 'ZDP_UNKNOWN';
  }

  switch (cluster.readUInt16LE(0)) {
    case 0x0000:
      return 'ZDP_REQ_NWK_ADDR';
    case 0x0001:
      return 'ZDP_REQ_IEEE_ADDR';
    case 0x0002:
      return 'ZDP_REQ_NODE_DESC';
    case 0x0003:
      return 'ZDP_REQ_POWER_DESC';
    case 0x0004:
      return 'ZDP_REQ_SIMPLE_DESC';
    case 0x0005:
      return 'ZDP_REQ_ACTIVE_EP';
    case 0x0006:
      return 'ZDP_REQ_MATCH_DESC';
    case 0x0010:
      return 'ZDP_REQ_COMPLEX_DESC';
    case 0x0011:
      return 'ZDP_REQ_USER_DESC';
    case 0x0012:
      return 'ZDP_REQ_DISCOVERY_CACHE';
    case 0x0013:
      return 'ZDP_REQ_DEVICE_ANNCE';
    case 0x0014:
      return 'ZDP_REQ_SET_USER_DESC';
    case 0x0015:
      return 'ZDP_REQ_SYSTEM_SERVER_DISC';
    case 0x0016:
      return 'ZDP_REQ_STORE_DISCOVERY';
    case 0x0017:
      return 'ZDP_REQ_STORE_NODE_DESC';
    case 0x0018:
      return 'ZDP_REQ_STORE_POWER_DESC';
    case 0x0019:
      return 'ZDP_REQ_STORE_ACTIVE_EP';
    case 0x001a:
      return 'ZDP_REQ_STORE_SIMPLE_DESC';
    case 0x001b:
      return 'ZDP_REQ_REMOVE_NODE_CACHE';
    case 0x001c:
      return 'ZDP_REQ_FIND_NODE_CACHE';
    case 0x001d:
      return 'ZDP_REQ_EXT_SIMPLE_DESC';
    case 0x001e:
      return 'ZDP_REQ_EXT_ACTIVE_EP';
    case 0x001f:
      return 'ZDP_REQ_PARENT_ANNCE';
    case 0x0020:
      return 'ZDP_REQ_END_DEVICE_BIND';
    case 0x0021:
      return 'ZDP_REQ_BIND';
    case 0x0022:
      return 'ZDP_REQ_UNBIND';
    case 0x0023:
      return 'ZDP_REQ_BIND_REGISTER';
    case 0x0024:
      return 'ZDP_REQ_REPLACE_DEVICE';
    case 0x0025:
      return 'ZDP_REQ_STORE_BAK_BIND_ENTRY';
    case 0x0026:
      return 'ZDP_REQ_REMOVE_BAK_BIND_ENTRY';
    case 0x0027:
      return 'ZDP_REQ_BACKUP_BIND_TABLE';
    case 0x0028:
      return 'ZDP_REQ_RECOVER_BIND_TABLE';
    case 0x0029:
      return 'ZDP_REQ_BACKUP_SOURCE_BIND';
    case 0x002a:
      return 'ZDP_REQ_RECOVER_SOURCE_BIND';
    case 0x002b:
      return 'ZDP_REQ_CLEAR_ALL_BINDINGS';
    case 0x0030:
      return 'ZDP_REQ_MGMT_NWK_DISC';
    case 0x0031:
      return 'ZDP_REQ_MGMT_LQI';
    case 0x0032:
      return 'ZDP_REQ_MGMT_RTG';
    case 0x0033:
      return 'ZDP_REQ_MGMT_BIND';
    case 0x0034:
      return 'ZDP_REQ_MGMT_LEAVE';
    case 0x0035:
      return 'ZDP_REQ_MGMT_DIRECT_JOIN';
    case 0x0036:
      return 'ZDP_REQ_MGMT_PERMIT_JOIN';
    case 0x0037:
      return 'ZDP_REQ_MGMT_CACHE';
    case 0x0038:
      return 'ZDP_REQ_MGMT_NWKUPDATE';
    case 0x0039:
      return 'ZDP_REQ_MGMT_NWKUPDATE_ENH';
    case 0x003a:
      return 'ZDP_REQ_MGMT_IEEE_JOIN_LIST';
    case 0x003c:
      return 'ZDP_REQ_MGMT_NWK_BEACON_SURVEY';
    case 0x0040:
      return 'ZDP_REQ_SECURITY_START_KEY_NEGOTIATION';
    case 0x0041:
      return 'ZDP_REQ_SECURITY_GET_AUTH_TOKEN';
    case 0x0042:
      return 'ZDP_REQ_SECURITY_GET_AUTH_LEVEL';
    case 0x0043:
      return 'ZDP_REQ_SECURITY_SET_CONFIGURATION';
    case 0x0044:
      return 'ZDP_REQ_SECURITY_GET_CONFIGURATION';
    case 0x0045:
      return 'ZDP_REQ_SECURITY_START_KEY_UPDATE';
    case 0x0046:
      return 'ZDP_REQ_SECURITY_DECOMMISSION';
    case 0x0047:
      return 'ZDP_REQ_SECURITY_CHALLENGE';

    case 0x8000:
      return 'ZDP_RSP_NWK_ADDR';
    case 0x8001:
      return 'ZDP_RSP_IEEE_ADDR';
    case 0x8002:
      return 'ZDP_RSP_NODE_DESC';
    case 0x8003:
      return 'ZDP_RSP_POWER_DESC';
    case 0x8004:
      return 'ZDP_RSP_SIMPLE_DESC';
    case 0x8005:
      return 'ZDP_RSP_ACTIVE_EP';
    case 0x8006:
      return 'ZDP_RSP_MATCH_DESC';
    case 0x8010:
      return 'ZDP_RSP_COMPLEX_DESC';
    case 0x8011:
      return 'ZDP_RSP_USER_DESC';
    case 0x8012:
      return 'ZDP_RSP_DISCOVERY_CACHE';
    case 0x8014:
      return 'ZDP_RSP_CONF_USER_DESC';
    case 0x8015:
      return 'ZDP_RSP_SYSTEM_SERVER_DISC';
    case 0x8016:
      return 'ZDP_RSP_STORE_DISCOVERY';
    case 0x8017:
      return 'ZDP_RSP_STORE_NODE_DESC';
    case 0x8018:
      return 'ZDP_RSP_STORE_POWER_DESC';
    case 0x8019:
      return 'ZDP_RSP_STORE_ACTIVE_EP';
    case 0x801a:
      return 'ZDP_RSP_STORE_SIMPLE_DESC';
    case 0x801b:
      return 'ZDP_RSP_REMOVE_NODE_CACHE';
    case 0x801c:
      return 'ZDP_RSP_FIND_NODE_CACHE';
    case 0x801d:
      return 'ZDP_RSP_EXT_SIMPLE_DESC';
    case 0x801e:
      return 'ZDP_RSP_EXT_ACTIVE_EP';
    case 0x801f:
      return 'ZDP_RSP_PARENT_ANNCE';
    case 0x8020:
      return 'ZDP_RSP_END_DEVICE_BIND';
    case 0x8021:
      return 'ZDP_RSP_BIND';
    case 0x8022:
      return 'ZDP_RSP_UNBIND';
    case 0x8023:
      return 'ZDP_RSP_BIND_REGISTER';
    case 0x8024:
      return 'ZDP_RSP_REPLACE_DEVICE';
    case 0x8025:
      return 'ZDP_RSP_STORE_BAK_BIND_ENTRY';
    case 0x8026:
      return 'ZDP_RSP_REMOVE_BAK_BIND_ENTRY';
    case 0x8027:
      return 'ZDP_RSP_BACKUP_BIND_TABLE';
    case 0x8028:
      return 'ZDP_RSP_RECOVER_BIND_TABLE';
    case 0x8029:
      return 'ZDP_RSP_BACKUP_SOURCE_BIND';
    case 0x802a:
      return 'ZDP_RSP_RECOVER_SOURCE_BIND';
    case 0x802b:
      return 'ZDP_RSP_CLEAR_ALL_BINDINGS';
    case 0x8030:
      return 'ZDP_RSP_MGMT_NWK_DISC';
    case 0x8031:
      return 'ZDP_RSP_MGMT_LQI';
    case 0x8032:
      return 'ZDP_RSP_MGMT_RTG';
    case 0x8033:
      return 'ZDP_RSP_MGMT_BIND';
    case 0x8034:
      return 'ZDP_RSP_MGMT_LEAVE';
    case 0x8035:
      return 'ZDP_RSP_MGMT_DIRECT_JOIN';
    case 0x8036:
      return 'ZDP_RSP_MGMT_PERMIT_JOIN';
    case 0x8037:
      return 'ZDP_RSP_MGMT_CACHE';
    case 0x8038:
      return 'NOT_MGMT_NWKUPDATE';
    case 0x8039:
      return 'NOT_MGMT_NWKUPDATE_ENH';
    case 0x803a:
      return 'ZDP_RSP_MGMT_IEEE_JOIN_LIST';
    case 0x803b:
      return 'NOT_MGMT_UNSOLICITED_NWKUPDATE';
    case 0x803c:
      return 'ZDP_RSP_MGMT_NWK_BEACON_SURVEY';
    case 0x8040:
      return 'ZDP_RSP_SECURITY_START_KEY_NEGOTIATION';
    case 0x8041:
      return 'ZDP_RSP_SECURITY_GET_AUTH_TOKEN';
    case 0x8042:
      return 'ZDP_RSP_SECURITY_GET_AUTH_LEVEL';
    case 0x8043:
      return 'ZDP_RSP_SECURITY_SET_CONFIGURATION';
    case 0x8044:
      return 'ZDP_RSP_SECURITY_GET_CONFIGURATION';
    case 0x8045:
      return 'ZDP_RSP_SECURITY_START_KEY_UPDATE';
    case 0x8046:
      return 'ZDP_RSP_SECURITY_DECOMMISSION';
    case 0x8047:
      return 'ZDP_RSP_SECURITY_CHALLENGE';

    default:
      return 'ZDP_UNKNOWN';
  }
};

types.zbee_aps_cmd = packet => {
  switch (packet?.id[0]) {
    case 0x01:
      return 'APS_CMD_SKKE1';
    case 0x02:
      return 'APS_CMD_SKKE2';
    case 0x03:
      return 'APS_CMD_SKKE3';
    case 0x04:
      return 'APS_CMD_SKKE4';
    case 0x05:
      return 'APS_CMD_TRANSPORT_KEY';
    case 0x06:
      return 'APS_CMD_UPDATE_DEVICE';
    case 0x07:
      return 'APS_CMD_REMOVE_DEVICE';
    case 0x08:
      return 'APS_CMD_REQUEST_KEY';
    case 0x09:
      return 'APS_CMD_SWITCH_KEY';
    case 0x0a:
      return 'APS_CMD_EA_INIT_CHLNG';
    case 0x0b:
      return 'APS_CMD_EA_RSP_CHLNG';
    case 0x0c:
      return 'APS_CMD_EA_INIT_MAC_DATA';
    case 0x0d:
      return 'APS_CMD_EA_RSP_MAC_DATA';
    case 0x0e:
      return 'APS_CMD_TUNNEL';
    case 0x0f:
      return 'APS_CMD_VERIFY_KEY';
    case 0x10:
      return 'APS_CMD_CONFIRM_KEY';
    case 0x11:
      return 'APS_CMD_RELAY_MSG_DOWNSTREAM';
    case 0x12:
      return 'APS_CMD_RELAY_MSG_UPSTREAM';
    default:
      return 'APS_CMD_UNKNOWN';
  }
};

types.zbee_aps = packet => {
  if (packet?.zbee_zcl) {
    return types.zbee_zcl(packet.zbee_zcl);
  } else if (packet?.zbee_zdp) {
    return types.zbee_zdp(packet.zbee_zdp, packet.cluster);
  }

  switch (packet?.fc.type) {
    case 0x0:
      return 'APS_DATA';
    case 0x1:
      if (Buffer.isBuffer(packet.data)) {
        return 'APS_CMD'; // still encrypted
      } else {
        return types.zbee_aps_cmd(packet.cmd);
      }
    case 0x2:
      return 'APS_ACK';
    default:
      return 'APS_UNKNOWN';
  }
};

types.zbee_nwk_cmd = packet => {
  switch (packet?.id[0]) {
    case 0x01:
      return 'NWK_CMD_ROUTE_REQ';
    case 0x02:
      return 'NWK_CMD_ROUTE_REPLY';
    case 0x03:
      return 'NWK_CMD_NWK_STATUS';
    case 0x04:
      return 'NWK_CMD_LEAVE';
    case 0x05:
      return 'NWK_CMD_ROUTE_RECORD';
    case 0x06:
      return 'NWK_CMD_REJOIN_REQ';
    case 0x07:
      return 'NWK_CMD_REJOIN_RSP';
    case 0x08:
      return 'NWK_CMD_LINK_STATUS';
    case 0x09:
      return 'NWK_CMD_NWK_REPORT';
    case 0x0a:
      return 'NWK_CMD_NWK_UPDATE';
    case 0x0b:
      return 'NWK_CMD_ED_TIMEOUT_REQUEST';
    case 0x0c:
      return 'NWK_CMD_ED_TIMEOUT_RSPONSE';
    case 0x0d:
      return 'NWK_CMD_LINK_PWR_DELTA';
    case 0x0e:
      return 'NWK_CMD_COMMISSIONING_REQUEST';
    case 0x0f:
      return 'NWK_CMD_COMMISSIONING_RSPONSE';
    default:
      return 'NWK_CMD_UNKNOWN';
  }
};

types.zbee_nwk = packet => {
  if (packet?.zbee_aps) {
    return types.zbee_aps(packet.zbee_aps);
  }

  switch (packet?.fc.type) {
    case 0x0:
      return 'NWK_DATA';
    case 0x1:
      if (Buffer.isBuffer(packet.data)) {
        return 'NWK_CMD'; // still encrypted
      } else {
        return types.zbee_nwk_cmd(packet.cmd);
      }
    default:
      return 'NWK_UNKNOWN';
  }
};

types.wpan_cmd = packet => {
  switch (packet?.id[0]) {
    case 0x01:
      return 'WPAN_CMD_ASSOC_REQ';
    case 0x02:
      return 'WPAN_CMD_ASSOC_RSP';
    case 0x03:
      return 'WPAN_CMD_DISASSOC_REQ';
    case 0x04:
      return 'WPAN_CMD_DATA_REQ';
    case 0x05:
      return 'WPAN_CMD_PAN_ID_CONFLICT';
    case 0x06:
      return 'WPAN_CMD_ORPHAN_NOTIFICATION';
    case 0x07:
      return 'WPAN_CMD_BEACON_REQ';
    case 0x08:
      return 'WPAN_CMD_COORD_REALIGN';
    case 0x09:
      return 'WPAN_CMD_GTS_REQ';
    default:
      return 'WPAN_CMD';
  }
};

types.wpan = packet => {
  if (packet?.zbee_nwk) {
    return types.zbee_nwk(packet.zbee_nwk);
  }

  switch (packet?.fc.type) {
    case 0x0:
      return 'WPAN_BEACON';
    case 0x1:
      return 'WPAN_DATA';
    case 0x2:
      return 'WPAN_ACK';
    case 0x3:
      return types.wpan_cmd(packet?.cmd);
    default:
      return 'WPAN_UNKNOWN';
  }
};

types.zep = packet => {
  if (packet?.wpan) {
    return types.wpan(packet?.wpan);
  }

  return 'ZEP_UNKNOWN';
};

/**
 * Determine the type of a ZigBee packet
 *
 * By default it will parse the data as a IEEE 802.15.4 Low-Rate Wireless PAN (WPAN) packet.
 * Other packet types, like ZigBee Encapsulation Protocol (ZEP) packets, can be parsed by specifying the type.
 *
 * @param {Buffer|object} packet the ZigBee packet data
 * @param {string} [type='wpan'] the type of packet to determine the type for
 * @returns {string} the type of packet
 */
export default function type(packet, type = 'wpan') {
  if (Buffer.isBuffer(packet)) {
    packet = parsePacket(packet, type);
  }

  if (!(type in types)) {
    throw new TypeError(`Unknown packet type: ${type}`);
  }

  return types[type](packet);
}

import { stdinMiddleware } from './utils.js';
export const command = {
  command: 'type [data]',
  desc: 'Determine Packet Type',
  builder: yargs => stdinMiddleware(yargs
    .option('type', {
      desc: 'Type of packet to determine the type for',
      type: 'string',
      choices: Object.keys(types),
      default: 'zep'
    }), { desc: 'Packet to determine the type for' })
    .example('$0 type 4558020113fffe0029d84f48995f78359c000a91aa000000000000000000000502003ffecb', 'Determine the type of ZigBee Encapsulation Protocol (ZEP) packet')
    .example('echo -n 4558020113fffe0029d84f48995f78359c000a91aa000000000000000000000502003ffecb | $0 type', 'Determine the type of a ZigBee Encapsulation Protocol (ZEP) packet from stdin')
    .version(false)
    .help(),
  handler: argv => {
    console.log(type(argv.data, argv.type));
  }
};

import { Buffer } from 'node:buffer';
import { fromHex } from './utils.js';
import { types } from './type.js';

/*
  Zigbee Cluster Library cluster IDs, human readable attribute names and wire data types.

  cluster.attrs maps attribute IDs to { id, name, type, encode, decode }.
  cluster.get(id) returns the name and cluster.attr(id) returns the full entry.
  Type is the numeric ZCL data type code.
  The codecs translate between JavaScript values and the attribute value bytes
  in Zigbee wire order, with the attribute ID and type byte supplied by the frame.
  parse.js uses the codecs from type.js to read attribute records. cap.js emits
  the parsed values and exposes Buffer values in big-endian order.

  Collections use { elementType, elements } and structures use [{ type, value }].
  Both take numeric ZCL type codes. Bitmap and octet values use Buffer.

  Sources:

  - docs/zigbee-cluster-library-spec.pdf (ZCL revision 8)
  - https://www.rfwireless-world.com/Terminology/Zigbee-Cluster-ID-list.html
  - https://www.bolukan.nl/?p=354
  - https://github.com/zigbeer/zcl-id/blob/master/definitions/common.json
  - https://e2e.ti.com/cfs-file/__key/communityserver-discussions-components-files/158/7608.ZigbeeClustersList_2D00_V0_5F00_1.xlsx
  - https://github.com/espressif/esp-zigbee-sdk
  - https://csa-iot.org/wp-content/uploads/2019/12/07-5123-06-zigbee-cluster-library-specification.pdf
  - https://zigbeealliance.org/wp-content/uploads/2019/12/docs-07-5356-19-0zse-zigbee-smart-energy-profile-specification.pdf
  - https://github.com/Koenkk/zigbee-herdsman/blob/8f5faffa813ccbefe16b1de88a9832ecfe1ab6bf/src/zspec/zcl/definition/cluster.ts
*/

const type = Object.fromEntries(Object.values(types.data).map(({ id, name }) => [name, id]));

const globalAttrs = [
  [0xfffd, 'Cluster Revision', type.uint16],
  [0xfffe, 'Attribute Reporting Status', type.enum8]
];

const sclDefs = [ // simple cluster definitions
  [0x0000, 'Basic', [[0x0000, 'ZCL Version', type.uint8], [0x0001, 'Application Version', type.uint8], [0x0002, 'Stack Version', type.uint8], [0x0003, 'HW Version', type.uint8], [0x0004, 'Manufacturer Name', type.characterString], [0x0005, 'Model Identifier', type.characterString], [0x0006, 'Date Code', type.characterString], [0x0007, 'Power Source', type.enum8], [0x0008, 'Generic Device Class', type.enum8], [0x0009, 'Generic Device Type', type.enum8], [0x000a, 'Product Code', type.octetString], [0x000b, 'Product URL', type.characterString], [0x000c, 'Manufacturer Version Details', type.characterString], [0x000d, 'Serial Number', type.characterString], [0x000e, 'Product Label', type.characterString], [0x0010, 'Location Description', type.characterString], [0x0011, 'Physical Environment', type.enum8], [0x0012, 'Device Enabled', type.boolean], [0x0013, 'Alarm Mask', type.bitmap8], [0x0014, 'Disable Local Config.', type.bitmap8], [0x4000, 'SW Build', type.characterString]]],
  [0x0001, 'Power Configuration', [[0x0000, 'Mains Voltage', type.uint16], [0x0001, 'Mains Frequency', type.uint8], [0x0020, 'Battery Voltage', type.uint8], [0x0021, 'Battery Percentage Remaining', type.uint8], [0x0030, 'Battery Manufacturer', type.characterString], [0x0031, 'Battery Size', type.enum8], [0x0032, 'Battery A Hr Rating', type.uint16], [0x0033, 'Battery Quantity', type.uint8], [0x0034, 'Battery Rated Voltage', type.uint8], [0x0035, 'Battery Alarm Mask', type.bitmap8], [0x0036, 'Battery Voltage Min. Threshold', type.uint8], [0x0037, 'Battery Voltage Threshold1', type.uint8], [0x0038, 'Battery Voltage Threshold2', type.uint8], [0x0039, 'Battery Voltage Threshold3', type.uint8], [0x003a, 'Battery Percentage Min. Threshold', type.uint8], [0x003b, 'Battery Percentage Threshold1', type.uint8], [0x003c, 'Battery Percentage Threshold2', type.uint8], [0x003d, 'Battery Percentage Threshold3', type.uint8], [0x003e, 'Battery Alarm State', type.bitmap32], [0x0040, 'Battery2 Voltage', type.uint8], [0x0050, 'Battery2 Manufacturer', type.characterString], [0x0060, 'Battery3 Voltage', type.uint8], [0x0070, 'Battery3 Manufacturer', type.characterString]]],
  [0x0002, 'Device Temperature Configuration', []],
  [0x0003, 'Identify', [[0x0000, 'Identify Time', type.uint16]]],
  [0x0004, 'Groups', [[0x0000, 'Name Support', type.bitmap8]]],
  [0x0005, 'Scenes', [[0x0000, 'Scene Count', type.uint8], [0x0001, 'Current Scene', type.uint8], [0x0002, 'Current Group', type.uint16], [0x0003, 'Scene Valid', type.boolean], [0x0004, 'Name Support', type.bitmap8], [0x0005, 'Last Configured By', type.ieeeAddress]]],
  [0x0006, 'On/Off', [[0x0000, 'On/Off', type.boolean], [0x4000, 'Global Scene Control', type.boolean], [0x4001, 'On Time', type.uint16], [0x4002, 'Off Wait Time', type.uint16], [0x4003, 'Start Up On Off', type.enum8]]],
  [0x0007, 'On/Off Switch Configuration', []],
  [0x0008, 'Level Control', [[0x0000, 'Current Level', type.uint8], [0x0001, 'Remaining Time', type.uint16], [0x0002, 'Min. Level', type.uint8], [0x0003, 'Max. Level', type.uint8], [0x0004, 'Current Frequency', type.uint16], [0x0005, 'Min. Frequency', type.uint16], [0x0006, 'Max. Frequency', type.uint16], [0x000f, 'Options', type.bitmap8], [0x0010, 'On Off Transition Time', type.uint16], [0x0011, 'On Level', type.uint8], [0x0012, 'On Transition Time', type.uint16], [0x0013, 'Off Transition Time', type.uint16], [0x0014, 'Default Move Rate', type.uint8], [0x4000, 'Start Up Current Level', type.uint8]]],
  [0x0009, 'Alarms', []],
  [0x000a, 'Time', [[0x0000, 'Time', type.utc], [0x0001, 'Time Status', type.bitmap8], [0x0002, 'Time Zone', type.int32], [0x0003, 'Dst. Start', type.uint32], [0x0004, 'Dst. End', type.uint32], [0x0005, 'Dst. Shift', type.int32], [0x0006, 'Standard Time', type.uint32], [0x0007, 'Local Time', type.uint32], [0x0008, 'Last Set Time', type.utc], [0x0009, 'Valid Until Time', type.utc]]],
  [0x000b, 'RSSI Location', []],
  [0x000c, 'Analog Input', [[0x001c, 'Description', type.characterString], [0x0041, 'Max. Present Value', type.float32], [0x0045, 'Min. Present Value', type.float32], [0x0051, 'Out of Service', type.boolean], [0x0055, 'Present Value', type.float32], [0x0067, 'Reliability', type.enum8], [0x006a, 'Resolution', type.float32], [0x006f, 'Status Flags', type.bitmap8], [0x0075, 'Engineering Units', type.enum16], [0x0100, 'Application Type', type.uint32]]],
  [0x000d, 'Analog Output', [[0x001c, 'Description', type.characterString], [0x0041, 'Max. Present Value', type.float32], [0x0045, 'Min. Present Value', type.float32], [0x0051, 'Out of Service', type.boolean], [0x0055, 'Present Value', type.float32], [0x0057, 'Priority Array', type.array], [0x0067, 'Reliability', type.enum8], [0x0068, 'Relinquish Default', type.float32], [0x006a, 'Resolution', type.float32], [0x006f, 'Status Flags', type.bitmap8], [0x0075, 'Engineering Units', type.enum16], [0x0100, 'Application Type', type.uint32]]],
  [0x000e, 'Analog Value', [[0x001c, 'Description', type.characterString], [0x0051, 'Out of Service', type.boolean], [0x0055, 'Present Value', type.float32], [0x0057, 'Priority Array', type.array], [0x0067, 'Reliability', type.enum8], [0x0068, 'Relinquish Default', type.float32], [0x006f, 'Status Flags', type.bitmap8], [0x0075, 'Engineering Units', type.enum16], [0x0100, 'Application Type', type.uint32]]],
  [0x000f, 'Binary Input', [[0x0004, 'Active Text', type.characterString], [0x0051, 'Out of Service', type.boolean], [0x0054, 'Polarity', type.enum8], [0x0055, 'Present Value', type.boolean], [0x0067, 'Reliability', type.enum8], [0x006f, 'Status Flags', type.bitmap8], [0x0100, 'Application Type', type.uint32]]],
  [0x0010, 'Binary Output', []],
  [0x0011, 'Binary Value', []],
  [0x0012, 'Multistate Input', []],
  [0x0013, 'Multistate Output', []],
  [0x0014, 'Multistate Value', [[0x000e, 'State Text', type.array], [0x001c, 'Description', type.characterString], [0x004a, 'Number of States', type.uint16], [0x0051, 'Out of Service', type.boolean], [0x0055, 'Present Value', type.uint16], [0x0057, 'Priority Array', type.array], [0x0067, 'Reliability', type.enum8], [0x0068, 'Relinquish Default', type.uint16], [0x006f, 'Status Flags', type.bitmap8], [0x0100, 'Application Type', type.uint32]]],
  [0x0015, 'Commissioning', [[0x0000, 'Short Address', type.uint16], [0x0001, 'Extended PAN ID', type.ieeeAddress], [0x0002, 'PAN ID', type.uint16], [0x0003, 'Channel Mask', type.bitmap32], [0x0004, 'Protocol Version', type.uint8], [0x0005, 'Stack Profile', type.uint8], [0x0006, 'Startup Control', type.enum8], [0x0010, 'Trust Center Address', type.ieeeAddress], [0x0011, 'Trust Center Master Key', type.securityKey], [0x0012, 'Network Key', type.securityKey], [0x0013, 'Use Insecure Join', type.boolean], [0x0014, 'Pre-configured Link Key', type.securityKey], [0x0015, 'Network Key Seq Num.', type.uint8], [0x0016, 'Network Key Type', type.enum8], [0x0017, 'Network Manager Address', type.uint16], [0x0020, 'Scan Attempts', type.uint8], [0x0021, 'Time Between Scans', type.uint16], [0x0022, 'Rejoin Interval', type.uint16], [0x0023, 'Max. Rejoin Interval', type.uint16], [0x0030, 'Indirect Poll Rate', type.uint16], [0x0031, 'Parent Retry Threshold', type.uint8], [0x0040, 'Concentrator Flag', type.boolean], [0x0041, 'Concentrator Radius', type.uint8], [0x0042, 'Concentrator Discovery Time', type.uint8]]],
  [0x0016, 'Partition', []],
  [0x0019, 'OTA Upgrade', [[0x0000, 'Upgrade Server ID', type.ieeeAddress], [0x0001, 'File Offset', type.uint32], [0x0002, 'File Version', type.uint32], [0x0003, 'Stack Version', type.uint16], [0x0004, 'Downloaded File Version', type.uint32], [0x0005, 'Downloaded Stack Version', type.uint16], [0x0006, 'Image Status', type.enum8], [0x0007, 'Manufacturer ID', type.uint16], [0x0008, 'Image Type', type.uint16], [0x0009, 'Minimum Block Period', type.uint16], [0x000a, 'Image Stamp', type.uint32], [0x000b, 'Upgrade Activation Policy', type.enum8], [0x000c, 'Upgrade Timeout Policy', type.enum8]]],
  [0x001a, 'Power Profile', []],
  [0x001b, 'EN50523 Appliance Control', []],
  [0x0020, 'Poll Control', [[0x0000, 'Check-in Interval', type.uint32], [0x0001, 'Long Poll Interval', type.uint32], [0x0002, 'Short Poll Interval', type.uint16], [0x0003, 'Fast Poll Timeout', type.uint16]]],
  [0x0021, 'Green power', []],
  [0x0022, 'Mobile Device Configuration', []],
  [0x0023, 'Neighbor Cleaning', []],
  [0x0024, 'Nearest Gateway', []],
  [0x0100, 'Shade Configuration', [[0x0000, 'Physical Closed Limit', type.uint16], [0x0001, 'Motor Step Size', type.uint8], [0x0002, 'Status', type.bitmap8], [0x0010, 'Closed Limit', type.uint16], [0x0011, 'Mode', type.enum8]]],
  [0x0101, 'Door Lock', [[0x0000, 'Lock State', type.enum8], [0x0001, 'Lock Type', type.enum8], [0x0002, 'Actuator Enabled', type.boolean], [0x0003, 'Door State', type.enum8], [0x0004, 'Num. of Door Open Events', type.uint32], [0x0005, 'Num. of Door Closed Events', type.uint32], [0x0006, 'Open Period', type.uint16], [0x0010, 'Number of Log Records Supported', type.uint16], [0x0011, 'Num. Total Users', type.uint16], [0x0012, 'Num. Pin Users', type.uint16], [0x0013, 'Number of RFID Users Supported', type.uint16], [0x0014, 'Num. Week Day Schedule Per User', type.uint8], [0x0015, 'Num. Year Day Schedule Per User', type.uint8], [0x0016, 'Num. Holiday Schedule', type.uint8], [0x0017, 'Max. Pin Len', type.uint8], [0x0018, 'Min. Pin Len', type.uint8], [0x0019, 'Max. RFID Code Length', type.uint8], [0x001a, 'Min. RFID Code Length', type.uint8], [0x0020, 'Enable Logging', type.boolean], [0x0021, 'Language', type.characterString], [0x0022, 'Led Settings', type.uint8], [0x0023, 'Auto Relock Time', type.uint32], [0x0024, 'Sound Volume', type.uint8], [0x0025, 'Operating Mode', type.enum8], [0x0026, 'Operation Modes Supported', type.bitmap16], [0x0027, 'Default Configuration Register', type.bitmap16], [0x0028, 'Enable Local Programming', type.boolean], [0x0029, 'Enable One Touch Locking', type.boolean], [0x0030, 'Wrong Code Entry Limit', type.uint8], [0x0031, 'User Code Temporary Disable Time', type.uint8], [0x0032, 'Send Pin Over The Air', type.boolean], [0x0033, 'Require Pin Rf', type.boolean], [0x0034, 'Security Level', type.enum8], [0x0040, 'Alarm Mask', type.bitmap16], [0x0041, 'Keypad Operation Event Mask', type.bitmap16], [0x0042, 'Rf Operation Event Mask', type.bitmap16], [0x0043, 'Manual Operation Event Mask', type.bitmap16], [0x0044, 'RFID Operation Event Mask', type.bitmap16], [0x0045, 'Keypad Programming Event Mask', type.bitmap16], [0x0046, 'Rf Programming Event Mask', type.bitmap16], [0x0047, 'RFID Programming Event Mask', type.bitmap16]]],
  [0x0102, 'Window Covering', [[0x0000, 'Window Covering Type', type.enum8], [0x0001, 'Physical Closed Limit Lift', type.uint16], [0x0002, 'Phy. Closed Limit Tilt', type.uint16], [0x0003, 'Current Position Lift', type.uint16], [0x0004, 'Current Position Tilt', type.uint16], [0x0005, 'Number of Actuations Lift', type.uint16], [0x0006, 'Number of Actuations Tilt', type.uint16], [0x0007, 'Config. Status', type.bitmap8], [0x0008, 'Current Position Lift Percentage', type.uint8], [0x0009, 'Current Position Tilt Percentage', type.uint8], [0x0010, 'Installed Open Limit Lift', type.uint16], [0x0011, 'Installed Closed Limit Lift', type.uint16], [0x0012, 'Installed Open Limit Tilt', type.uint16], [0x0013, 'Installed Closed Limit Tilt', type.uint16], [0x0014, 'Velocity', type.uint16], [0x0015, 'Acceleration Time', type.uint16], [0x0016, 'Deceleration Time', type.uint16], [0x0017, 'Mode', type.bitmap8], [0x0018, 'Intermediate Setpoints Lift', type.octetString], [0x0019, 'Intermediate Setpoints Tilt', type.octetString]]],
  [0x0200, 'Pump Configuration and Control', []],
  [0x0201, 'Thermostat', [[0x0000, 'Local Temperature', type.int16], [0x0001, 'Outdoor Temperature', type.int16], [0x0002, 'Occupancy', type.bitmap8], [0x0003, 'Abs Min. Heat Setpoint Limit', type.int16], [0x0004, 'Abs Max. Heat Setpoint Limit', type.int16], [0x0005, 'Abs Min. Cool Setpoint Limit', type.int16], [0x0006, 'Abs Max. Cool Setpoint Limit', type.int16], [0x0007, 'Pi Cooling Demand', type.uint8], [0x0008, 'Pi Heating Demand', type.uint8], [0x0009, 'HVAC System Type Configuration', type.bitmap8], [0x0010, 'Local Temperature Calibration', type.int8], [0x0011, 'Occupied Cooling Setpoint', type.int16], [0x0012, 'Occupied Heating Setpoint', type.int16], [0x0013, 'Unoccupied Cooling Setpoint', type.int16], [0x0014, 'Unoccupied Heating Setpoint', type.int16], [0x0015, 'Min. Heat Setpoint Limit', type.int16], [0x0016, 'Max. Heat Setpoint Limit', type.int16], [0x0017, 'Min. Cool Setpoint Limit', type.int16], [0x0018, 'Max. Cool Setpoint Limit', type.int16], [0x0019, 'Min. Setpoint Dead Band', type.int8], [0x001a, 'Remote Sensing', type.bitmap8], [0x001b, 'Control Sequence of Operation', type.enum8], [0x001c, 'System Mode', type.enum8], [0x001d, 'Alarm Mask', type.bitmap8], [0x001e, 'Running Mode', type.enum8], [0x0020, 'Start of Week', type.enum8], [0x0021, 'Number of Weekly Transitions', type.uint8], [0x0022, 'Number of Daily Transitions', type.uint8], [0x0023, 'Temperature Setpoint Hold', type.enum8], [0x0024, 'Temperature Setpoint Hold Duration', type.uint16], [0x0025, 'Thermostat Programming Operation Mode', type.bitmap8], [0x0029, 'Thermostat Running State', type.bitmap16], [0x0030, 'Setpoint Change Source', type.enum8], [0x0031, 'Setpoint Change Amount', type.int16], [0x0032, 'Setpoint Change Source Timestamp', type.utc], [0x0034, 'Occupied Setback', type.uint8], [0x0035, 'Occupied Setback Min.', type.uint8], [0x0036, 'Occupied Setback Max.', type.uint8], [0x0037, 'Unoccupied Setback', type.uint8], [0x0038, 'Unoccupied Setback Min.', type.uint8], [0x0039, 'Unoccupied Setback Max.', type.uint8], [0x003a, 'Emergency Heat Delta', type.uint8], [0x0040, 'Ac Type', type.enum8], [0x0041, 'Ac Capacity', type.uint16], [0x0042, 'Ac Refrigerant Type', type.enum8], [0x0043, 'Ac Compressor Type', type.enum8], [0x0044, 'Ac Error Code', type.bitmap32], [0x0045, 'Ac Louver Position', type.enum8], [0x0046, 'Ac Coil Temperature', type.int16], [0x0047, 'Ac Capacity Format', type.enum8]]],
  [0x0202, 'Fan Control', [[0x0000, 'Fan Mode', type.enum8], [0x0001, 'Fan Mode Sequence', type.enum8]]],
  [0x0203, 'Dehumidification Control', [[0x0000, 'Relative Humidity', type.uint8], [0x0001, 'Dehumidification Cooling', type.uint8], [0x0010, 'RH-Dehumidification Setpoint', type.uint8], [0x0011, 'Relative Humidity Mode', type.enum8], [0x0012, 'Dehumidification Lockout', type.enum8], [0x0013, 'Dehumidification Hysteresis', type.uint8], [0x0014, 'Dehumidification Max. Cool', type.uint8], [0x0015, 'Relative Humidity Display', type.enum8]]],
  [0x0204, 'Thermostat User Interface Configuration', [[0x0000, 'Temperature Display Mode', type.enum8], [0x0001, 'Keypad Lockout', type.enum8], [0x0002, 'Schedule Programming Visibility', type.enum8]]],
  [0x0300, 'Color Control', [[0x0000, 'Current Hue', type.uint8], [0x0001, 'Current Saturation', type.uint8], [0x0002, 'Remaining Time', type.uint16], [0x0003, 'Current X', type.uint16], [0x0004, 'Current Y', type.uint16], [0x0005, 'Drift Compensation', type.enum8], [0x0006, 'Compensation Text', type.characterString], [0x0007, 'Color Temperature', type.uint16], [0x0008, 'Color Mode', type.enum8], [0x000f, 'Options', type.bitmap8], [0x4000, 'Enhanced Current Hue', type.uint16], [0x4001, 'Enhanced Color Mode', type.enum8], [0x4002, 'Color Loop Active', type.uint8], [0x4003, 'Color Loop Direction', type.uint8], [0x4004, 'Color Loop Time', type.uint16], [0x4005, 'Color Loop Start Enhanced Hue', type.uint16], [0x4006, 'Color Loop Stored Enhanced Hue', type.uint16], [0x400a, 'Color Capabilities', type.bitmap16], [0x400b, 'Color Temp. Physical Min. Mireds', type.uint16], [0x400c, 'Color Temp. Physical Max. Mireds', type.uint16], [0x400d, 'Couple Color Temp. To Level Min. Mireds', type.uint16], [0x4010, 'Start Up Color Temperature Mireds', type.uint16]]],
  [0x0301, 'Ballast Configuration', []],
  [0x0400, 'Illuminance Measurement', [[0x0000, 'Measured Value', type.uint16], [0x0001, 'Min. Measured Value', type.uint16], [0x0002, 'Max. Measured Value', type.uint16], [0x0003, 'Tolerance', type.uint16], [0x0004, 'Light Sensor Type', type.enum8]]],
  [0x0401, 'Illuminance Level Sensing', []],
  [0x0402, 'Temperature Measurement', [[0x0000, 'Value', type.int16], [0x0001, 'Min. Value', type.int16], [0x0002, 'Max. Value', type.int16], [0x0003, 'Tolerance', type.uint16]]],
  [0x0403, 'Pressure Measurement', [[0x0000, 'Value', type.int16], [0x0001, 'Min. Value', type.int16], [0x0002, 'Max. Value', type.int16], [0x0003, 'Tolerance', type.uint16], [0x0010, 'Scaled Value', type.int16], [0x0011, 'Min. Scaled Value', type.int16], [0x0012, 'Max. Scaled Value', type.int16], [0x0013, 'Scaled Tolerance', type.uint16], [0x0014, 'Scale', type.int8]]],
  [0x0404, 'Flow Measurement', [[0x0000, 'Value', type.uint16], [0x0001, 'Min. Value', type.uint16], [0x0002, 'Max. Value', type.uint16], [0x0003, 'Tolerance', type.uint16]]],
  [0x0405, 'Relative Humidity Measurement', [[0x0000, 'Measurement Value', type.uint16], [0x0001, 'Measurement Min. Value', type.uint16], [0x0002, 'Measurement Max. Value', type.uint16], [0x0003, 'Tolerance', type.uint16]]],
  [0x0406, 'Occupancy Sensing', [[0x0000, 'Occupancy', type.bitmap8], [0x0001, 'Occupancy Sensor Type', type.enum8], [0x0002, 'Occupancy Sensor Type Bitmap', type.bitmap8], [0x0010, 'PIR Occ. To Unocc. Delay', type.uint16], [0x0011, 'PIR Unocc. To Occ. Delay', type.uint16], [0x0012, 'PIR Unocc. To Occ. Threshold', type.uint8], [0x0020, 'Ultrasonic Occ. To Unocc. Delay', type.uint16], [0x0021, 'Ultrasonic Unocc. To Occ. Delay', type.uint16], [0x0022, 'Ultrasonic Unocc. To Occ. Threshold', type.uint8]]],
  [0x0500, 'IAS Zone', [[0x0000, 'Zone State', type.enum8], [0x0001, 'Zone Type', type.enum16], [0x0002, 'Zone Status', type.bitmap16], [0x0010, 'IAS CIE Address', type.ieeeAddress], [0x0011, 'Zone ID', type.uint8], [0x0012, 'Number of Zone Sensitivity Levels Supported', type.uint8], [0x0013, 'Current Zone Sensitivity Level', type.uint8]]],
  [0x0501, 'IAS ACE', []],
  [0x0502, 'IAS WD', [[0x0000, 'Max. Duration', type.uint16]]],
  [0x0600, 'Generic Tunnel', []],
  [0x0601, 'BACnet Protocol Tunnel', []],
  [0x0602, 'Analog Input (BACnet Regular)', []],
  [0x0603, 'Analog Input (BACnet Extended)', []],
  [0x0604, 'Analog Output (BACnet Regular)', []],
  [0x0605, 'Analog Output (BACnet Extended)', []],
  [0x0606, 'Analog Value (BACnet Regular)', []],
  [0x0607, 'Analog Value (BACnet Extended)', []],
  [0x0608, 'Binary Input (BACnet Regular)', []],
  [0x0609, 'Binary Input (BACnet Extended)', []],
  [0x060a, 'Binary Output (BACnet Regular)', []],
  [0x060b, 'Binary Output (BACnet Extended)', []],
  [0x060c, 'Binary Value (BACnet Regular)', []],
  [0x060d, 'Binary Value (BACnet Extended)', []],
  [0x060e, 'Multistate Input (BACnet Regular)', []],
  [0x060f, 'Multistate Input (BACnet Extended)', []],
  [0x0610, 'Multistate Output (BACnet Regular)', []],
  [0x0611, 'Multistate Output (BACnet Extended)', []],
  [0x0612, 'Multistate Value (BACnet Regular)', []],
  [0x0613, 'Multistate Value (BACnet Extended)', []],
  [0x0614, '11073 Protocol Tunnel', []],
  [0x0615, 'ISO 7816 Protocol Tunnel', []],
  [0x0617, 'Retail Tunnel', []],
  [0x0700, 'Price', [[0x0000, 'CLI Price Increase Randomize Minutes', type.uint8], [0x0001, 'CLI Price Decrease Randomize Minutes', type.uint8], [0x0002, 'CLI Commodity Type', type.enum8]]],
  [0x0701, 'Demand Response and Load Control', [[0x0000, 'Utility Enrollment Group', type.uint8], [0x0001, 'Start Randomization Minutes', type.uint8], [0x0002, 'End Randomization Minutes', type.uint8], [0x0003, 'Device Class Value', type.uint16]]],
  [0x0702, 'Metering (Smart Energy)', [[0x0000, 'Current Summation Delivered', type.uint48], [0x0001, 'Current Summation Received', type.uint48], [0x0300, 'Unit of Measure', type.enum8], [0x0301, 'Multiplier', type.uint24], [0x0302, 'Divisor', type.uint24], [0x0400, 'Instantaneous Demand', type.int24]]],
  [0x0703, 'Messaging (Smart Energy)', []],
  [0x0704, 'Tunneling (Smart Energy)', []],
  [0x0705, 'Prepayment (Smart Energy)', []],
  [0x0706, 'Energy Management', []],
  [0x0707, 'Calendar', []],
  [0x0708, 'Device Management', []],
  [0x0709, 'Events', []],
  [0x070a, 'MDU pairing', []],
  [0x070b, 'Sub-GHz (Smart Energy)', []],
  [0x0800, 'Key Establishment (Smart Energy)', []],
  [0x0900, 'Information (Telecom)', []],
  [0x0904, 'Voice Over ZigBee', []],
  [0x0905, 'Chatting', []],
  [0x0b00, 'EN50523 Appliance Identification', []],
  [0x0b01, 'Meter Identification', [[0x0000, 'Company Name', type.characterString], [0x0001, 'Meter Type', type.uint16], [0x0004, 'Data Quality', type.uint16], [0x0005, 'Customer Name', type.characterString], [0x0006, 'Model', type.octetString], [0x0007, 'Part Number', type.octetString], [0x0008, 'Product Revision', type.octetString]]],
  [0x0b02, 'EN50523 Appliance Events and Alerts', []],
  [0x0b03, 'EN50523 Appliance Statistics', []],
  [0x0b04, 'Electrical Measurement', [[0x0000, 'Measurement Type', type.bitmap32], [0x0100, 'Dc Voltage', type.int16], [0x0101, 'Dc Voltage Min.', type.int16], [0x0102, 'Dc Voltage Max.', type.int16], [0x0103, 'Dc Current', type.int16], [0x0104, 'Dc Current Min.', type.int16], [0x0105, 'Dc Current Max.', type.int16], [0x0106, 'DC Power', type.int16], [0x0107, 'Dc Power Min.', type.int16], [0x0108, 'Dc Power Max.', type.int16], [0x0200, 'Dc Voltage Multiplier', type.uint16], [0x0201, 'Dc Voltage Divisor', type.uint16], [0x0202, 'Dc Current Multiplier', type.uint16], [0x0203, 'Dc Current Divisor', type.uint16], [0x0204, 'Dc Power Multiplier', type.uint16], [0x0205, 'Dc Power Divisor', type.uint16], [0x0300, 'Ac Frequency', type.uint16], [0x0301, 'Ac Frequency Min.', type.uint16], [0x0302, 'Ac Frequency Max.', type.uint16], [0x0303, 'Neutral Current', type.uint16], [0x0304, 'Total Active Power', type.int32], [0x0305, 'Total Reactive Power', type.int32], [0x0306, 'Total Apparent Power', type.uint32], [0x0307, 'Measured1st Harmonic Current', type.int16], [0x0308, 'Measured3rd Harmonic Current', type.int16], [0x0309, 'Measured5th Harmonic Current', type.int16], [0x030a, 'Measured7th Harmonic Current', type.int16], [0x030b, 'Measured9th Harmonic Current', type.int16], [0x030c, 'Measured11th Harmonic Current', type.int16], [0x030d, 'Measured Phase1st Harmonic Current', type.int16], [0x030e, 'Measured Phase3rd Harmonic Current', type.int16], [0x030f, 'Measured Phase5th Harmonic Current', type.int16], [0x0310, 'Measured Phase7th Harmonic Current', type.int16], [0x0311, 'Measured Phase9th Harmonic Current', type.int16], [0x0312, 'Measured Phase11th Harmonic Current', type.int16], [0x0400, 'Ac Frequency Multiplier', type.uint16], [0x0401, 'Ac Frequency Divisor', type.uint16], [0x0402, 'Power Multiplier', type.uint32], [0x0403, 'Power Divisor', type.uint32], [0x0404, 'Harmonic Current Multiplier', type.int8], [0x0405, 'Phase Harmonic Current Multiplier', type.int8], [0x0501, 'Line Current', type.uint16], [0x0502, 'Active Current', type.int16], [0x0503, 'Reactive Current', type.int16], [0x0505, 'RMS Voltage', type.uint16], [0x0506, 'RMS Voltage Min.', type.uint16], [0x0507, 'RMS Voltage Max.', type.uint16], [0x0508, 'RMS Current', type.uint16], [0x0509, 'RMS Current Min.', type.uint16], [0x050a, 'RMS Current Max.', type.uint16], [0x050b, 'Active Power', type.int16], [0x050c, 'Active Power Min.', type.int16], [0x050d, 'Active Power Max.', type.int16], [0x050e, 'Reactive Power', type.int16], [0x050f, 'Apparent Power', type.uint16], [0x0510, 'Power Factor', type.int8], [0x0511, 'Average RMS Voltage Measurement Period', type.uint16], [0x0512, 'Average RMS Over Voltage Counter', type.uint16], [0x0513, 'Average RMS Under Voltage Counter', type.uint16], [0x0514, 'RMS Extreme Over Voltage Period', type.uint16], [0x0515, 'RMS Extreme Under Voltage Period', type.uint16], [0x0516, 'RMS Voltage Sag Period', type.uint16], [0x0517, 'RMS Voltage Swell Period', type.uint16], [0x0600, 'AC Voltage Multiplier', type.uint16], [0x0601, 'AC Voltage Divisor', type.uint16], [0x0602, 'AC Current Multiplier', type.uint16], [0x0603, 'AC Current Divisor', type.uint16], [0x0604, 'AC Power Multiplier', type.uint16], [0x0605, 'AC Power Divisor', type.uint16], [0x0700, 'Dc Overload Alarms Mask', type.bitmap8], [0x0701, 'Dc Voltage Overload', type.int16], [0x0702, 'Dc Current Overload', type.int16], [0x0800, 'Ac Alarms Mask', type.bitmap16], [0x0801, 'Ac Voltage Overload', type.int16], [0x0802, 'Ac Current Overload', type.int16], [0x0803, 'Ac Active Power Overload', type.int16], [0x0804, 'Ac Reactive Power Overload', type.int16], [0x0805, 'Average RMS Over Voltage', type.int16], [0x0806, 'Average RMS Under Voltage', type.int16], [0x0807, 'RMS Extreme Over Voltage', type.int16], [0x0808, 'RMS Extreme Under Voltage', type.int16], [0x0809, 'RMS Voltage Sag', type.int16], [0x080a, 'RMS Voltage Swell', type.int16], [0x0901, 'Line Current PH B', type.uint16], [0x0902, 'Active Current PH B', type.int16], [0x0903, 'Reactive Current PH B', type.int16], [0x0905, 'RMS Voltage PHB', type.uint16], [0x0906, 'RMS Voltage Min. PH B', type.uint16], [0x0907, 'RMS Voltage Max. PH B', type.uint16], [0x0908, 'RMS Current PHB', type.uint16], [0x0909, 'RMS Current Min. PH B', type.uint16], [0x090a, 'RMS Current Max. PH B', type.uint16], [0x090b, 'Active Power PH B', type.int16], [0x090c, 'Active Power Min. PH B', type.int16], [0x090d, 'Active Power Max. PH B', type.int16], [0x090e, 'Reactive Power PH B', type.int16], [0x090f, 'Apparent Power PH B', type.uint16], [0x0910, 'Power Factor PH B', type.int8], [0x0911, 'Average RMS Voltage Measurement Period PHB', type.uint16], [0x0912, 'Average RMS Over Voltage Counter PH B', type.uint16], [0x0913, 'Average RMS Under Voltage Counter PH B', type.uint16], [0x0914, 'RMS Extreme Over Voltage Period PH B', type.uint16], [0x0915, 'RMS Extreme Under Voltage Period PH B', type.uint16], [0x0916, 'RMS Voltage Sag Period PH B', type.uint16], [0x0917, 'RMS Voltage Swell Period PH B', type.uint16], [0x0a01, 'Line Current PH C', type.uint16], [0x0a02, 'Active Current PH C', type.int16], [0x0a03, 'Reactive Current PH C', type.int16], [0x0a05, 'RMS Voltage PHC', type.uint16], [0x0a06, 'RMS Voltage Min. PH C', type.uint16], [0x0a07, 'RMS Voltage Max. PH C', type.uint16], [0x0a08, 'RMS Current PHC', type.uint16], [0x0a09, 'RMS Current Min. PH C', type.uint16], [0x0a0a, 'RMS Current Max. PH C', type.uint16], [0x0a0b, 'Active Power PH C', type.int16], [0x0a0c, 'Active Power Min. PH C', type.int16], [0x0a0d, 'Active Power Max. PH C', type.int16], [0x0a0e, 'Reactive Power PH C', type.int16], [0x0a0f, 'Apparent Power PH C', type.uint16], [0x0a10, 'Power Factor PH C', type.int8], [0x0a11, 'Average RMS Voltage Measurement Period PH C', type.uint16], [0x0a12, 'Average RMS Over Voltage Counter PH C', type.uint16], [0x0a13, 'Average RMS Under Voltage Counter PH C', type.uint16], [0x0a14, 'RMS Extreme Over Voltage Period PH C', type.uint16], [0x0a15, 'RMS Extreme Under Voltage Period PH C', type.uint16], [0x0a16, 'RMS Voltage Sag Period PH C', type.uint16], [0x0a17, 'RMS Voltage Swell Period PH C', type.uint16]]],
  [0x0b05, 'Diagnostics', [[0x0000, 'Number of Resets', type.uint16], [0x0001, 'Persistent Memory Writes', type.uint16], [0x0100, 'Mac Rx. Broadcast', type.uint32], [0x0101, 'Mac Tx. Broadcast', type.uint32], [0x0102, 'Mac Rx. Unicast', type.uint32], [0x0103, 'Mac Tx. Unicast', type.uint32], [0x0104, 'Mac Tx. Unicast Retry', type.uint16], [0x0105, 'Mac Tx. Unicast Fail', type.uint16], [0x0106, 'APS Rx. Broadcast', type.uint16], [0x0107, 'APS Tx. Broadcast', type.uint16], [0x0108, 'APS Rx. Unicast', type.uint16], [0x0109, 'APS Tx. Unicast Success', type.uint16], [0x010a, 'APS Tx. Unicast Retry', type.uint16], [0x010b, 'APS Tx. Unicast Fail', type.uint16], [0x010c, 'Route Discovery Initiated', type.uint16], [0x010d, 'Neighbor Added', type.uint16], [0x010e, 'Neighbor Removed', type.uint16], [0x010f, 'Neighbor Stale', type.uint16], [0x0110, 'Join Indication', type.uint16], [0x0111, 'Child Moved', type.uint16], [0x0112, 'NWKFC Failure', type.uint16], [0x0113, 'APSFC Failure', type.uint16], [0x0114, 'APS Unauthorized Key', type.uint16], [0x0115, 'NWK Decrypt Failures', type.uint16], [0x0116, 'APS Decrypt Failures', type.uint16], [0x0117, 'Packet Buffer Allocate Failures', type.uint16], [0x0118, 'Relayed Unicast', type.uint16], [0x0119, 'Phy. to MAC Queue Limit Reached', type.uint16], [0x011a, 'Packet Validate Drop Count', type.uint16], [0x011b, 'Average Mac Retry Per APS', type.uint16], [0x011c, 'Last LQI', type.uint8], [0x011d, 'Last RSSI', type.int8]]],
  [0x1000, 'Touchlink Commissioning', []],
  [0x0025, 'Keepalive', []],
  [0x0901, 'Data sharing', []],
  [0x0902, 'Gaming', []],
  [0x0903, 'Data rate control', []],
  [0x0a01, 'Payment', []],
  [0x0a02, 'Billing', []],
  [0xfc00, 'Sample MFG Specific', []],
  [0xfc01, 'OTA Configuration', []],
  [0xfc02, 'MFGLIB', []]
];

const clusters = new Map();
const toId = id => typeof id === 'number' ? id : fromHex(id).readUInt16BE(0);

function addCluster(id, name, attrs) {
  attrs = [...(attrs || []), ...globalAttrs].reduce((map, [id, name, type]) => {
    const { encode, decode } = types.data[type];
    return map.set(id, { id, name, type, encode, decode });
  }, new Map());

  const cluster = {
    id, name, attrs,
    attr: id => attrs.get(toId(id)),
    get: id => attrs.get(toId(id))?.name
  };

  clusters.set(id, cluster);
}
for (const sclDef of sclDefs) {
  addCluster(...sclDef);
}

const genericClusters = {};
for (const [key, name] of [
  ['standard', 'ZigBee Standard'],
  ['reserved', 'Reserved'],
  ['manufacturer', 'Manufacturer Specific']
]) {
  genericClusters[key] = { name, generic: key };
}

/**
 * Get the cluster definition for the given cluster ID.
 *
 * @param {(number|string|Buffer)} id the cluster ID to get the name for
 * @returns {object} the cluster definition or a generic cluster description
 */
export default function get(id) {
  id = toId(id);

  // determine the specific cluster name or a generic one based on the cluster ID range:
  // - 0x0000 to 0x7FFF - ZigBee standard cluster
  // - 0x8000 to 0xFBFF - Reserved for future use
  // - 0xFC00 to 0xFFFF - Manufacturer specific
  return clusters.get(id) || (
    id <= 0x7FFF ? genericClusters.standard :
      id <= 0xFBFF ? genericClusters.reserved :
        genericClusters.manufacturer
  );
}

export const command = {
  command: 'cluster <id>',
  desc: 'Cluster Library Name and Attributes',
  builder: yargs => yargs
    .positional('id', {
      desc: 'Cluster ID',
      type: 'string'
    })
    .option('attributes', {
      alias: ['a', 'attr', 'attrs'],
      desc: 'List the attributes for the given cluster',
      type: 'boolean'
    })
    .example('$0 cluster 0x0001', 'Get the name for the given cluster ID')
    .example('$0 cluster 0x0002 --attributes', 'Get the name and attributes for the given cluster ID')
    .version(false)
    .help(),
  handler: argv => {
    const cluster = get(argv.id);
    if (!cluster) {
      console.log(`Cluster ${argv.id} not found`);
      process.exit(1);
    }

    console.log(cluster.name);
    if (argv.attributes && cluster.attrs?.size) {
      for (const { id, name } of cluster.attrs.values()) {
        console.log(`  ${name} (0x${id.toString(16).padStart(4, '0')})`);
      }
    }
  }
};

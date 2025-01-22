import { Buffer } from 'node:buffer';
import { fromHex, toHex } from './utils.js';

/*
  Cluster & attributes ID to human readable name mapping joined from multiple sources:

  - https://www.rfwireless-world.com/Terminology/Zigbee-Cluster-ID-list.html
  - https://www.bolukan.nl/?p=354
  - https://github.com/zigbeer/zcl-id/blob/master/definitions/common.json
  - https://e2e.ti.com/cfs-file/__key/communityserver-discussions-components-files/158/7608.ZigbeeClustersList_2D00_V0_5F00_1.xlsx
  - https://github.com/espressif/esp-zigbee-sdk
*/

const sclDefs = [ // simple cluster definitions
  [0x0000, 'Basic', [[0x0000, 'ZCL Version'], [0x0001, 'Application Version'], [0x0002, 'Stack Version'], [0x0003, 'HW Version'], [0x0004, 'Manufacturer Name'], [0x0005, 'Model Identifier'], [0x0006, 'Date Code'], [0x0007, 'Power Source'], [0x0008, 'Generic Device Class'], [0x0009, 'Generic Device Type'], [0x000a, 'Product Code'], [0x000b, 'Product URL'], [0x000c, 'Manufacturer Version Details'], [0x000d, 'Serial Number'], [0x000e, 'Product Label'], [0x0010, 'Location Description'], [0x0011, 'Physical Environment'], [0x0012, 'Device Enabled'], [0x0013, 'Alarm Mask'], [0x0014, 'Disable Local Config.'], [0x4000, 'SW Build']]],
  [0x0001, 'Power Configuration', [[0x0000, 'Mains Voltage'], [0x0001, 'Mains Frequency'], [0x0020, 'Battery Voltage'], [0x0021, 'Battery Percentage Remaining'], [0x0030, 'Battery Manufacturer'], [0x0031, 'Battery Size'], [0x0032, 'Battery A Hr Rating'], [0x0033, 'Battery Quantity'], [0x0034, 'Battery Rated Voltage'], [0x0035, 'Battery Alarm Mask'], [0x0036, 'Battery Voltage Min. Threshold'], [0x0037, 'Battery Voltage Threshold1'], [0x0038, 'Battery Voltage Threshold2'], [0x0039, 'Battery Voltage Threshold3'], [0x003a, 'Battery Percentage Min. Threshold'], [0x003b, 'Battery Percentage Threshold1'], [0x003c, 'Battery Percentage Threshold2'], [0x003d, 'Battery Percentage Threshold3'], [0x003e, 'Battery Alarm State'], [0x0040, 'Battery2 Voltage'], [0x0050, 'Battery2 Manufacturer'], [0x0060, 'Battery3 Voltage'], [0x0070, 'Battery3 Manufacturer']]],
  [0x0002, 'Device Temperature Configuration', []],
  [0x0003, 'Identify', [[0x0000, 'Identify Time']]],
  [0x0004, 'Groups', []],
  [0x0005, 'Scenes', [[0x0000, 'Scene Count'], [0x0001, 'Current Scene'], [0x0002, 'Current Group'], [0x0003, 'Scene Valid'], [0x0004, 'Name Support'], [0x0005, 'Last Configured By']]],
  [0x0006, 'On/Off', [[0x4000, 'Global Scene Control'], [0x4001, 'On Time'], [0x4002, 'Off Wait Time'], [0x4003, 'Start Up On Off']]],
  [0x0007, 'On/Off Switch Configuration', []],
  [0x0008, 'Level Control', [[0x0000, 'Current Level'], [0x0001, 'Remaining Time'], [0x0002, 'Min. Level'], [0x0003, 'Max. Level'], [0x0004, 'Current Frequency'], [0x0005, 'Min. Frequency'], [0x0006, 'Max. Frequency'], [0x0010, 'On Off Transition Time'], [0x0011, 'On Level'], [0x0012, 'On Transition Time'], [0x0013, 'Off Transition Time'], [0x0014, 'Default Move Rate'], [0x4000, 'Start Up Current Level'], [0xefff, 'Move Status']]],
  [0x0009, 'Alarms', []],
  [0x000a, 'Time', [[0x0000, 'Time'], [0x0001, 'Time Status'], [0x0002, 'Time Zone'], [0x0003, 'Dst. Start'], [0x0004, 'Dst. End'], [0x0005, 'Dst. Shift'], [0x0006, 'Standard Time'], [0x0007, 'Local Time'], [0x0008, 'Last Set Time'], [0x0009, 'Valid Until Time']]],
  [0x000b, 'RSSI', []],
  [0x000c, 'Analog Input', [[0x001c, 'Description'], [0x0041, 'Max. Present Value'], [0x0045, 'Min. Present Value'], [0x0051, 'Out of Service'], [0x0055, 'Present Value'], [0x0067, 'Reliability'], [0x006a, 'Resolution'], [0x006f, 'Status Flags'], [0x0075, 'Engineering Units'], [0x0100, 'Application Type']]],
  [0x000d, 'Analog Output', [[0x001c, 'Description'], [0x0041, 'Max. Present Value'], [0x0045, 'Min. Present Value'], [0x0051, 'Out of Service'], [0x0055, 'Present Value'], [0x0057, 'Priority Array'], [0x0067, 'Reliability'], [0x0068, 'Relinquish Default'], [0x006a, 'Resolution'], [0x006f, 'Status Flags'], [0x0075, 'Engineering Units'], [0x0100, 'Application Type']]],
  [0x000e, 'Analog Value', [[0x001c, 'Description'], [0x0051, 'Out of Service'], [0x0055, 'Present Value'], [0x0057, 'Priority Array'], [0x0067, 'Reliability'], [0x0068, 'Relinquish Default'], [0x006f, 'Status Flags'], [0x0075, 'Engineering Units'], [0x0100, 'Application Type']]],
  [0x000f, 'Binary Input', [[0x0004, 'Active Text'], [0x0051, 'Out of Service'], [0x0054, 'Polarity'], [0x0055, 'Present Value'], [0x0067, 'Reliability'], [0x0100, 'Application Type']]],
  [0x0010, 'Binary Output', []],
  [0x0011, 'Binary Value', []],
  [0x0012, 'Multistate Input', []],
  [0x0013, 'Multistate Output', []],
  [0x0014, 'Multistate Value', [[0x000e, 'State Text'], [0x001c, 'Description'], [0x004a, 'Number of States'], [0x0051, 'Out of Service'], [0x0055, 'Present Value'], [0x0057, 'Priority Array'], [0x0067, 'Reliability'], [0x0068, 'Relinquish Default'], [0x006f, 'Status Flags'], [0x0100, 'Application Type']]],
  [0x0015, 'Commissioning', [[0x0000, 'Short Address'], [0x0001, 'Extended PAN ID'], [0x0002, 'PAN ID'], [0x0003, 'Channel Mask'], [0x0004, 'Protocol Version'], [0x0005, 'Stack Profile'], [0x0006, 'Startup Control'], [0x0010, 'Trust Center Address'], [0x0011, 'Trust Center Master Key'], [0x0012, 'Network Key'], [0x0013, 'Use Insecure Join'], [0x0014, 'Pre-configured Link Key'], [0x0015, 'Network Key Seq Num.'], [0x0016, 'Network Key Type'], [0x0017, 'Network Manager Address'], [0x0020, 'Scan Attempts'], [0x0021, 'Time Between Scans'], [0x0022, 'Rejoin Interval'], [0x0023, 'Max. Rejoin Interval'], [0x0030, 'Indirect Poll Rate'], [0x0031, 'Parent Retry Threshold'], [0x0040, 'Concentrator Flag'], [0x0041, 'Concentrator Radius'], [0x0042, 'Concentrator Discovery Time']]],
  [0x0016, 'Partition', []],
  [0x0019, 'OTA Upgrade', [[0x0000, 'Server'], [0x0001, 'File Offset'], [0x0002, 'File Version'], [0x0003, 'Stack Version'], [0x0004, 'Downloaded File Version'], [0x0005, 'Downloaded Stack Version'], [0x0006, 'Image Status'], [0x0007, 'Manufacture'], [0x0008, 'Image Type'], [0x0009, 'Min. Block Reque'], [0x000a, 'Image Stamp'], [0x000b, 'Upgrade Activation Policy'], [0x000c, 'Upgrade Timeout Policy'], [0xfff3, 'Server Endpoint'], [0xfff2, 'Server Addr.'], [0xfff1, 'Client Data'], [0xfff0, 'Server Data']]],
  [0x001a, 'Power Profile', []],
  [0x001b, 'EN50523 Appliance Control', []],
  [0x0020, 'Poll Control', []],
  [0x0021, 'Green power', []],
  [0x0022, 'Mobile Device Configuration', []],
  [0x0023, 'Neighbor Cleaning', []],
  [0x0024, 'Nearest Gateway', []],
  [0x0100, 'Shade Configuration', [[0x0000, 'Physical Closed Limit'], [0x0001, 'Motor Step Size'], [0x0002, 'Status']]],
  [0x0101, 'Door Lock', [[0x0000, 'Lock State'], [0x0001, 'Lock Type'], [0x0002, 'Actuator Enabled'], [0x0003, 'Door State'], [0x0004, 'Num. of Door Open Events'], [0x0005, 'Num. of Door Closed Events'], [0x0006, 'Open Period'], [0x0010, 'Number of Log Records Supported'], [0x0011, 'Num. Total Users'], [0x0012, 'Num. Pin Users'], [0x0013, 'Number of RFID Users Supported'], [0x0014, 'Num. Week Day Schedule Per User'], [0x0015, 'Num. Year Day Schedule Per User'], [0x0016, 'Num. Holiday Schedule'], [0x0017, 'Max. Pin Len'], [0x0018, 'Min. Pin Len'], [0x0019, 'Max. RFID Code Length'], [0x0020, 'Enable Logging'], [0x0021, 'Language'], [0x0022, 'Led Settings'], [0x0023, 'Auto Relock Time'], [0x0024, 'Sound Volume'], [0x0025, 'Operating Mode'], [0x0026, 'Operation Modes Supported'], [0x0027, 'Default Configuration Register'], [0x0028, 'Enable Local Programming'], [0x0029, 'Enable One Touch Locking'], [0x0030, 'Wrong Code Entry Limit'], [0x0031, 'User Code Temporary Disable Time'], [0x0032, 'Send Pin Over The Air'], [0x0033, 'Require Pin Rf'], [0x0034, 'Security Level'], [0x0040, 'Alarm Mask'], [0x0041, 'Keypad Operation Event Mask'], [0x0042, 'Rf Operation Event Mask'], [0x0043, 'Manual Operation Event Mask'], [0x0044, 'RFID Operation Event Mask'], [0x0045, 'Keypad Programming Event Mask'], [0x0046, 'Rf Programming Event Mask'], [0x0047, 'RFID Programming Event Mask']]],
  [0x0102, 'Window Covering', [[0x0000, 'Window Covering Type'], [0x0001, 'Physical Closed Limit Lift'], [0x0002, 'Phy. Closed Limit Tilt'], [0x0003, 'Current Position Lift'], [0x0004, 'Current Position Tilt'], [0x0005, 'Number of Actuations Lift'], [0x0006, 'Number of Actuations Tilt'], [0x0007, 'Config. Status'], [0x0008, 'Current Position Lift Percentage'], [0x0009, 'Current Position Tilt Percentage'], [0x0010, 'Installed Open Limit Lift'], [0x0011, 'Installed Closed Limit Lift'], [0x0012, 'Installed Open Limit Tilt'], [0x0013, 'Installed Closed Limit Tilt'], [0x0014, 'Velocity'], [0x0015, 'Acceleration Time'], [0x0016, 'Deceleration Time'], [0x0017, 'Mode'], [0x0018, 'Intermediate Setpoints Lift'], [0x0019, 'Intermediate Setpoints Tilt']]],
  [0x0200, 'Pump Configuration and Control', []],
  [0x0201, 'Thermostat', [[0x0000, 'Local Temperature'], [0x0001, 'Outdoor Temperature'], [0x0002, 'Occupancy'], [0x0003, 'Abs Min. Heat Setpoint Limit'], [0x0004, 'Abs Max. Heat Setpoint Limit'], [0x0005, 'Abs Min. Cool Setpoint Limit'], [0x0006, 'Abs Max. Cool Setpoint Limit'], [0x0007, 'Pi Cooling Demand'], [0x0008, 'Pi Heating Demand'], [0x0009, 'HVAC System Type Configuration'], [0x0010, 'Local Temperature Calibration'], [0x0011, 'Occupied Cooling Setpoint'], [0x0012, 'Occupied Heating Setpoint'], [0x0013, 'Unoccupied Cooling Setpoint'], [0x0014, 'Unoccupied Heating Setpoint'], [0x0015, 'Min. Heat Setpoint Limit'], [0x0016, 'Max. Heat Setpoint Limit'], [0x0017, 'Min. Cool Setpoint Limit'], [0x0018, 'Max. Cool Setpoint Limit'], [0x0019, 'Min. Setpoint Dead Band'], [0x001a, 'Remote Sensing'], [0x001b, 'Control Sequence of Operation'], [0x001c, 'System Mode'], [0x001d, 'Alarm Mask'], [0x001e, 'Running Mode'], [0x0020, 'Start of Week'], [0x0021, 'Number of Weekly Transitions'], [0x0022, 'Number of Daily Transitions'], [0x0023, 'Temperature Setpoint Hold'], [0x0024, 'Temperature Setpoint Hold Duration'], [0x0025, 'Thermostat Programming Operation Mode'], [0x0029, 'Thermostat Running State'], [0x0030, 'Setpoint Change Source'], [0x0031, 'Setpoint Change Amount'], [0x0032, 'Setpoint Change Source Timestamp'], [0x0034, 'Occupied Setback'], [0x0035, 'Occupied Setback Min.'], [0x0036, 'Occupied Setback Max.'], [0x0037, 'Unoccupied Setback'], [0x0038, 'Unoccupied Setback Min.'], [0x0039, 'Unoccupied Setback Max.'], [0x003a, 'Emergency Heat Delta'], [0x0040, 'Ac Type'], [0x0041, 'Ac Capacity'], [0x0042, 'Ac Refrigerant Type'], [0x0043, 'Ac Compressor Type'], [0x0044, 'Ac Error Code'], [0x0045, 'Ac Louver Position'], [0x0046, 'Ac Coil Temperature'], [0x0047, 'Ac Capacity Format']]],
  [0x0202, 'Fan Control', [[0x0000, 'Fan Mode'], [0x0001, 'Fan Mode Sequence']]],
  [0x0203, 'Dehumidification Control', [[0x0000, 'Relative Humidity'], [0x0001, 'Dehumidification Cooling'], [0x0010, 'RH-Dehumidification Setpoint'], [0x0011, 'Relative Humidity Mode'], [0x0012, 'Dehumidification Lockout'], [0x0013, 'Dehumidification Hysteresis'], [0x0014, 'Dehumidification Max. Cool'], [0x0015, 'Relative Humidity Display']]],
  [0x0204, 'Thermostat User Interface Configuration', [[0x0000, 'Temperature Display Mode'], [0x0001, 'Keypad Lockout'], [0x0002, 'Schedule Programming Visibility']]],
  [0x0300, 'Color Control', [[0x0000, 'Current Hue'], [0x0001, 'Current Saturation'], [0x0002, 'Remaining Time'], [0x0003, 'Current X'], [0x0004, 'Current Y'], [0x0005, 'Drift Compensation'], [0x0006, 'Compensation Text'], [0x0007, 'Color Temperature'], [0x0008, 'Color Mode'], [0x000f, 'Options'], [0x4000, 'Enhanced Current Hue'], [0x4001, 'Enhanced Color Mode'], [0x4002, 'Color Loop Active'], [0x4003, 'Color Loop Direction'], [0x4004, 'Color Loop Time'], [0x4005, 'Color Loop Start Enhanced Hue'], [0x4006, 'Color Loop Stored Enhanced Hue'], [0x400a, 'Color Capabilities'], [0x400b, 'Color Temp. Physical Min. Mireds'], [0x400c, 'Color Temp. Physical Max. Mireds'], [0x400d, 'Couple Color Temp. To Level Min. Mireds'], [0x4010, 'Start Up Color Temperature Mireds']]],
  [0x0301, 'Ballast Configuration', []],
  [0x0400, 'Illuminance Measurement', [[0x0000, 'Measured Value'], [0x0001, 'Min. Measured Value'], [0x0002, 'Max. Measured Value'], [0x0003, 'Tolerance'], [0x0004, 'Light Sensor Type']]],
  [0x0401, 'Illuminance Level Sensing', []],
  [0x0402, 'Temperature Measurement', [[0x0000, 'Value'], [0x0001, 'Min. Value'], [0x0002, 'Max. Value'], [0x0003, 'Tolerance']]],
  [0x0403, 'Pressure Measurement', [[0x0000, 'Value'], [0x0001, 'Min. Value'], [0x0002, 'Max. Value'], [0x0003, 'Tolerance'], [0x0010, 'Scaled Value'], [0x0011, 'Min. Scaled Value'], [0x0012, 'Max. Scaled Value'], [0x0013, 'Scaled Tolerance'], [0x0014, 'Scale']]],
  [0x0404, 'Flow Measurement', [[0x0000, 'Value'], [0x0001, 'Min. Value'], [0x0002, 'Max. Value'], [0x0003, 'Tolerance']]],
  [0x0405, 'Relative Humidity', [[0x0000, 'Measurement Value'], [0x0001, 'Measurement Min. Value'], [0x0002, 'Measurement Max. Value'], [0x0003, 'Tolerance']]],
  [0x0406, 'Occupancy Sensing', [[0x0000, 'Occupancy'], [0x0001, 'Occupancy Sensor Type'], [0x0002, 'Occupancy Sensor Type Bitmap'], [0x0010, 'PIR Occ. To Unocc. Delay'], [0x0011, 'PIR Unocc. To Occ. Delay'], [0x0012, 'PIR Unocc. To Occ. Threshold']]],
  [0x0500, 'IAS Zone', [[0x0000, 'Zonestate'], [0x0001, 'Zonetype'], [0x0002, 'Zonestatus'], [0x0010, 'IAS CIE Address'], [0x0011, 'Zone ID'], [0x0012, 'Number of Zone Sensitivity Levels Supported'], [0x0013, 'Current Zone Sensitivity Level'], [0xeffe, 'Int Ctx.']]],
  [0x0501, 'IAS ACE', []],
  [0x0502, 'IAS WD', [[0x0000, 'Max. Duration']]],
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
  [0x0615, 'ISO 7818 Protocol Tunnel', []],
  [0x0617, 'Retail Tunnel', []],
  [0x0700, 'Price', [[0x0000, 'CLI Price Increase Randomize Minutes'], [0x0001, 'CLI Price Decrease Randomize Minutes'], [0x0002, 'CLI Commodity Type']]],
  [0x0701, 'Demand Response and Load Control', [[0x0000, 'Utility Enrollment Group'], [0x0001, 'Start Randomization Minutes'], [0x0002, 'Duration Randomization Minutes'], [0x0003, 'Device Class Value']]],
  [0x0702, 'Metering (Smart Energy)', []],
  [0x0703, 'Messaging (Smart Energy)', []],
  [0x0704, 'Tunneling (Smart Energy)', []],
  [0x0705, 'Key Establishment', []],
  [0x0706, 'Energy Management', []],
  [0x0707, 'Calender', []],
  [0x0708, 'Device Management', []],
  [0x0709, 'Events', []],
  [0x070a, 'MDU pairing', []],
  [0x0800, 'Key Establishment (Smart Energy)', []],
  [0x0900, 'Information (Telecom)', []],
  [0x0904, 'Voice Over ZigBee', []],
  [0x0905, 'Chatting', []],
  [0x0b00, 'EN50523 Appliance Identification', []],
  [0x0b01, 'Meter Identification', [[0x0000, 'Company Name'], [0x0001, 'Meter Type'], [0x0004, 'Data Quality'], [0x0005, 'Customer Name'], [0x0006, 'Model'], [0x0007, 'Part Number'], [0x0008, 'Product Revision']]],
  [0x0b02, 'EN50523 Appliance Events and Alerts', []],
  [0x0b03, 'EN50523 Appliance Statistics', []],
  [0x0b04, 'Electrical Measurement', [[0x0000, 'Measurement Type'], [0x0100, 'Dc Voltage'], [0x0101, 'Dc Voltage Min.'], [0x0102, 'Dc Voltage Max.'], [0x0103, 'Dc Current'], [0x0104, 'Dc Current Min.'], [0x0105, 'Dc Current Max.'], [0x0106, 'DC Power'], [0x0107, 'Dc Power Min.'], [0x0108, 'Dc Power Max.'], [0x0200, 'Dc Voltage Multiplier'], [0x0201, 'Dc Voltage Divisor'], [0x0202, 'Dc Current Multiplier'], [0x0203, 'Dc Current Divisor'], [0x0204, 'Dc Power Multiplier'], [0x0205, 'Dc Power Divisor'], [0x0300, 'Ac Frequency'], [0x0301, 'Ac Frequency Min.'], [0x0302, 'Ac Frequency Max.'], [0x0303, 'Neutral Current'], [0x0304, 'Total Active Power'], [0x0305, 'Total Reactive Power'], [0x0306, 'Total Apparent Power'], [0x0307, 'Measured1st Harmonic Current'], [0x0308, 'Measured3rd Harmonic Current'], [0x0309, 'Measured5th Harmonic Current'], [0x030a, 'Measured7th Harmonic Current'], [0x030b, 'Measured9th Harmonic Current'], [0x030c, 'Measured11th Harmonic Current'], [0x030d, 'Measured Phase1st Harmonic Current'], [0x030e, 'Measured Phase3rd Harmonic Current'], [0x030f, 'Measured Phase5th Harmonic Current'], [0x0310, 'Measured Phase7th Harmonic Current'], [0x0311, 'Measured Phase9th Harmonic Current'], [0x0312, 'Measured Phase11th Harmonic Current'], [0x0400, 'Ac Frequency Multiplier'], [0x0401, 'Ac Frequency Divisor'], [0x0402, 'Power Multiplier'], [0x0403, 'Power Divisor'], [0x0404, 'Harmonic Current Multiplier'], [0x0405, 'Phase Harmonic Current Multiplier'], [0x0501, 'Line Current'], [0x0502, 'Active Current'], [0x0503, 'Reactive Current'], [0x0505, 'RMS Voltage'], [0x0506, 'RMS Voltage Min.'], [0x0507, 'RMS Voltage Max.'], [0x0508, 'RMS Current'], [0x0509, 'RMS Current Min.'], [0x050a, 'RMS Current Max.'], [0x050c, 'Active Power Min.'], [0x050d, 'Active Power Max.'], [0x050e, 'Reactive Power'], [0x0510, 'Power Factor'], [0x0511, 'Average RMS Voltage Measurement Period'], [0x0512, 'Average RMS Over Voltage Counter'], [0x0513, 'Average RMS Under Voltage Counter'], [0x0514, 'RMS Extreme Over Voltage Period'], [0x0515, 'RMS Extreme Under Voltage Period'], [0x0516, 'RMS Voltage Sag Period'], [0x0517, 'RMS Voltage Swell Period'], [0x0600, 'AC Voltage Multiplier'], [0x0601, 'AC Voltage Divisor'], [0x0602, 'AC Current Multiplier'], [0x0603, 'AC Current Divisor'], [0x0604, 'AC Power Multiplier'], [0x0605, 'AC Power Divisor'], [0x0700, 'Dc Overload Alarms Mask'], [0x0701, 'Dc Voltage Overload'], [0x0702, 'Dc Current Overload'], [0x0800, 'Ac Alarms Mask'], [0x0801, 'Ac Voltage Overload'], [0x0802, 'Ac Current Overload'], [0x0803, 'Ac Active Power Overload'], [0x0804, 'Ac Reactive Power Overload'], [0x0805, 'Average RMS Over Voltage'], [0x0806, 'Average RMS Under Voltage'], [0x0807, 'RMS Extreme Over Voltage'], [0x0808, 'RMS Extreme Under Voltage'], [0x0809, 'RMS Voltage Sag'], [0x080a, 'RMS Voltage Swell'], [0x0901, 'Line Current PH B'], [0x0902, 'Active Current PH B'], [0x0903, 'Reactive Current PH B'], [0x0905, 'RMS Voltage PHB'], [0x0906, 'RMS Voltage Min. PH B'], [0x0907, 'RMS Voltage Max. PH B'], [0x0908, 'RMS Current PHB'], [0x0909, 'RMS Current Min. PH B'], [0x090a, 'RMS Current Max. PH B'], [0x090c, 'Active Power Min. PH B'], [0x090d, 'Active Power Max. PH B'], [0x090e, 'Reactive Power PH B'], [0x0910, 'Power Factor PH B'], [0x0911, 'Average RMS Voltage Measurement Period PHB'], [0x0912, 'Average RMS Over Voltage Counter PH B'], [0x0913, 'Average RMS Under Voltage Counter PH B'], [0x0914, 'RMS Extreme Over Voltage Period PH B'], [0x0915, 'RMS Extreme Under Voltage Period PH B'], [0x0916, 'RMS Voltage Sag Period PH B'], [0x0917, 'RMS Voltage Swell Period PH B'], [0x0a01, 'Line Current PH C'], [0x0a02, 'Active Current PH C'], [0x0a03, 'Reactive Current PH C'], [0x0a06, 'RMS Voltage Min. PH C'], [0x0a07, 'RMS Voltage Max. PH C'], [0x0a09, 'RMS Current Min. PH C'], [0x0a0a, 'RMS Current Max. PH C'], [0x0a0c, 'Active Power Min. PH C'], [0x0a0d, 'Active Power Max. PH C'], [0x0a0e, 'Reactive Power PH C'], [0x0a10, 'Power Factor PH C'], [0x0a12, 'Average RMS Over Voltage Counter PH C'], [0x0a13, 'Average RMS Under Voltage Counter PH C'], [0x0a14, 'RMS Extreme Over Voltage Period PH C'], [0x0a15, 'RMS Extreme Under Voltage Period PH C'], [0x0a16, 'RMS Voltage Sag Period PH C'], [0x0a17, 'RMS Voltage Swell Period PH C']]],
  [0x0b05, 'Diagnostics', [[0x0000, 'Number of Resets'], [0x0001, 'Persistent Memory Writes'], [0x0100, 'Mac Rx. Broadcast'], [0x0101, 'Mac Tx. Broadcast'], [0x0102, 'Mac Rx. Unicast'], [0x0103, 'Mac Tx. Unicast'], [0x0104, 'Mac Tx. Unicast Retry'], [0x0105, 'Mac Tx. Unicast Fail'], [0x0106, 'APS Rx. Broadcast'], [0x0107, 'APS Tx. Broadcast'], [0x0108, 'APS Rx. Unicast'], [0x0109, 'APS Tx. Unicast Success'], [0x010b, 'APS Tx. Unicast Fail'], [0x0110, 'Join Indication'], [0x0111, 'Child Moved'], [0x0112, 'NWKFC Failure'], [0x0113, 'APSFC Failure'], [0x0114, 'APS Unauthorized Key'], [0x0115, 'NWK Decrypt Failures'], [0x0116, 'APS Decrypt Failures'], [0x0117, 'Packet Buffer Allocate Failures'], [0x0118, 'Relayed Unicast'], [0x0119, 'Phy. to MAC Queue Limit Reached'], [0x011b, 'Average Mac Retry Per APS'], [0x011c, 'Last LQI'], [0x011d, 'Last RSSI']]],
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
function addCluster(id, name, attrs) {
  const cluster = {
    id, name, attrs: (attrs || []).reduce(
      (map, [id, name]) => map.set(id, name), new Map()),
    get: function(id) {
      if (typeof id !== 'number') {
        id = fromHex(id).readUInt16BE(0);
      }

      return id <= 0x3FFF ? cluster.attrs.get(id) :
        'Manufacturer Specific';
    }
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
 * Get the human readable name for the given cluster ID.
 *
 * @param {(number|string|Buffer)} id the cluster ID to get the name for
 * @returns {string} the human readable name of the cluster
 */
export default function get(id) {
  if (typeof id !== 'number') {
    id = fromHex(id).readUInt16BE(0);
  }

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

    process.stdout.write(cluster.name);
    if (argv.attributes && cluster.attrs?.length) {
      for (const [id, name] of cluster.attrs) {
        process.stdout.write(`\n  ${name} (0x${id.toString(16).padStart(4, '0')})`);
      }
    }
  }
};

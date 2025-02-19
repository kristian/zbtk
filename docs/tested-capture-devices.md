# Tested Capture Devices

This page lists supported and tested capture devices for the [`cap.js` tool](../README.md#zbtk-cap) and provides additional set-up instructions and hints.

Further devices, as for example listed for example in the [ZigBee2MQTT sniffing how-to](https://www.zigbee2mqtt.io/advanced/zigbee/04_sniff_zigbee_traffic.html), should be supported as well. Feel free to open a pull-request to add them to the list if you tested them successfully.

## Ubisys IEEE 802.15.4 Wireshark USB Stick

![Ubisys Wirehsark Stick](UbisysUSB.png)

| **Status** | ✅ Tested & Working |
| --- | --- |
| Operating Systems Tested | Windows, Linux (Debian) |
| Manufacturer | Ubisys |
| Homepage | https://www.ubisys.de/en/products/for-zigbee-product-developers/wireshark-usb-stick/ |
| Price | ~236,81€ |
| Pros / Cons | Pros: Out of the box solution, easy to set-up and configure / no tinkering required. Cons: Quite expensive, requires kernel driver patching on Linux |

Set-up according to [manufacturers instructions](https://www.ubisys.de/wp-content/uploads/ubisys-ieee802154-wireshark-manual.pdf). Only challenge was that when patching the `rndis_host.c` driver on Debian 12 "Bookworm", some `OID_*` constants in the driver have been renamed to `RNDIS_OID_*` instead, which had to be manually renamed in order for the new kernel package to compile. To fix the issue I had to do the following replacements:

```batch
sed -i 's/OID_STR(OID_/OID_STR(RNDIS_OID_/g' rndis_host.c
```

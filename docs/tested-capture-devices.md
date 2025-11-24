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
| Pros / Cons | Pros: Out of the box solution, registers as a network interface, easy to set-up and configure / no tinkering / no additional tools required. Cons: Quite expensive, requires kernel driver patching on Linux |

Set-up according to [manufacturers instructions](https://www.ubisys.de/wp-content/uploads/ubisys-ieee802154-wireshark-manual.pdf). Only challenge was that when patching the `rndis_host.c` driver on Debian 12 "Bookworm", some `OID_*` constants in the driver have been renamed to `RNDIS_OID_*` instead, which had to be manually renamed in order for the new kernel package to compile. To fix the issue I had to do the following replacements:

```batch
sed -i 's/OID_STR(OID_/OID_STR(RNDIS_OID_/g' rndis_host.c
```

As the stick registers as a network interface, it generates ZigBee Encapsulation Protocol (ZEP) packets in an UDP / IPv4 / Ethernet wrapper, thus run packet capture with:

```bash
# set the channel and pull the interface up
sudo ./ieee802154_options.sh -c 19
sudo ip link set dev enx001fee00295e up

# start capturing data
sudo tcpdump -n -i enx001fee00295e -s 0 -w - udp port 17754 | zbtk cap -u eth,ip4,udp,zep
```

## Generic CC2531 Dongle w/ TI Sniffer Firmware 

![CC2531 Dongle](cc2531.png)

| **Status** | ✅ Tested & Working |
| --- | --- |
| Operating Systems Tested | Linux (Debian) |
| Manufacturer | Generic / TI / Sonoff |
| Homepage | https://www.ti.com/product/en-us/CC2531 |
| Price | <10€ (!) |
| Pros / Cons | Pros: Very cheap, plenty of tool support. Cons: Requires FW flashing (+ flashing hardware / CC-Debugger or tinkering w/ Raspberry Pi), low throughput / weak hardware |

Flash the TI sniffing firmware according to the [instructions on Zigbee2MQTT](https://www.zigbee2mqtt.io/advanced/zigbee/04_sniff_zigbee_traffic.html#_1-flashing-the-cc2531-adapter). After flashing the stick will only work with `libusb`, so tools like `dumpcap` can access it. We recommend [`whsniff`](https://github.com/homewsn/whsniff) as it was specifically designed to generate a (P)CAP standard output stream from the TI CC2531 USB dongle w/ sniffer firmware:

```batch
sudo apt-get install libusb-1.0-0-dev
curl -L https://github.com/homewsn/whsniff/archive/v1.3.tar.gz | tar zx
cd whsniff-1.3
make
sudo make install
```

The stick outputs unwrapped WPAN packages, so no additional unwrapping of the frame will be required:

```bash
sudo whsniff -c 19 | zbtk cap
```

## SMLIGHT SLZB-06M Ethernet Dongle

![SMLIGHT SLZB-06M](smlight_slzb06m.png)

| **Status** | ✅ Tested & Working |
| --- | --- |
| Operating Systems Tested | Linux (Debian) |
| Manufacturer | SMLIGHT |
| Homepage | https://smlight.tech/product/slzb-06m |
| Price | ~38,50€ |
| Pros / Cons | Pros: *No* additional set-up required! Works out of the box via Ethernet / PoE or serial. Strong hardware / large throughput. Cons: More expensive than other options |

The SMLIGHT SLZB-06M is a true out of the box solution! We would recommend signing in to the web interface once to (OTA) update the firmware and radio firmware. ZigBee Toolkit should work with any EmberZNet and HUSBZB-1 adapters. [ZigBee2MQTT recommends](https://www.zigbee2mqtt.io/advanced/zigbee/04_sniff_zigbee_traffic.html#with-emberznet-and-husbzb-1-adapters) to use [`ember-zli` to sniff](https://github.com/Nerivec/ember-zli/wiki/Sniff), however Ember ZLI is not natively able to generate a (P)CAP stream to standard output (stdout), thus we recommend to use [`ember-sniff`](https://github.com/kristian/ember-sniff) as an alternative, providing a CLI similar to `whsniff` for CC2531 dongles:

```batch
npm install -g ember-sniff
```

Sniffing is as easy as connecting to the dongle via TCP. `ember-sniff` also outputs raw WPAN packets, thus no additional unwrapping of packets will be required:

```bash
ember-sniff -p tcp://192.168.1.152:6638 -c 19 | zbtk cap
```

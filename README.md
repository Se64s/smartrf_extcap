# smartrf_extcap
Interface to link Wireshark with HW with TI Packet Sniffer 2 FW without any other intermediate application.

## TI SmartRF Packet Sniffer
Official TI resources.
- [Packet Sniffer 2](https://www.ti.com/tool/download/PACKET-SNIFFER-2)
- [User Guide](https://software-dl.ti.com/lprf/packet_sniffer_2/docs/user_guide/html/index.html)

## Features
This extcap allows the setup of the packet sniffer software into the following configurations:
- Interface for 802.15.4 O-QPSK 2.4 GHz
- Interface for 802.15.4g GFSK 100 Kbps 868 MHz

## Core Concepts
This tool was developed to offer an easy interface for sniffing packets for ZigBee networks. Another key point of this project is to allow the user the possibility to modify the tool without the need to mount any development environment.

The development of this tool has been done with the TI eval board [LAUNCHXL-CC1352R1](https://www.ti.com/tool/LAUNCHXL-CC1352R1). Other TI boards may be compatible but may require some changes at PHY config defines.

## Requirements
- Python 3 (tested on 3.8.1).
- [pySerial](https://pyserial.readthedocs.io/en/latest/index.html) (tested on 3.4).

## Getting Started
Guide of use for script-based extcap [here](https://www.wireshark.org/docs/wsdg_html_chunked/ChCaptureExtcap.html#ChCaptureExtcapWindowsShell)

## TODO
- Extend the PHY interface to support other protocols.

## Contact
Please contact me for any suggestion or idea about this tool.
- sebmorgal@gmail.com
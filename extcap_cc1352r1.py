#!/usr/bin/env python
""" Extcap script for Wireshark to handle SmartRF packet sniffer 2 based sniffers (CC1352r1 platforms).

This script interfaces hardware that uses the MCU CC1352r1  and the sniffer application firmware provided by TI:
https://www.ti.com/tool/download/PACKET-SNIFFER-2

This software has been developed and tested only on windows platforms.

Deployment instructions: 
https://www.wireshark.org/docs/wsdg_html_chunked/ChCaptureExtcap.html#ChCaptureExtcapWindowsShell
"""

from __future__ import print_function

import sys
import os
import re
import argparse
import time
import struct
import serial.tools.list_ports
import logging
import smart_rf_driver as rfDriver

__author__ = "Sebastián Del Moral"
__copyright__ = ""
__credits__ = ["Sebastián Del Moral"]
__license__ = "MIT License"
__version__ = "0.0.1"
__maintainer__ = "Sebastián Del Moral"
__email__ = "sebmorgal@gmail.com"
__status__ = "Development"

# Wireshark standard error codes
ERROR_USAGE          = 0
ERROR_ARG            = 1
ERROR_INTERFACE      = 2
ERROR_FIFO           = 3
ERROR_DELAY          = 4

# Wireshark command codes for controls
CTRL_CMD_INITIALIZED = 0
CTRL_CMD_SET         = 1
CTRL_CMD_ADD         = 2
CTRL_CMD_REMOVE      = 3
CTRL_CMD_ENABLE      = 4
CTRL_CMD_DISABLE     = 5
CTRL_CMD_STATUSBAR   = 6
CTRL_CMD_INFORMATION = 7
CTRL_CMD_WARNING     = 8
CTRL_CMD_ERROR       = 9

# User defined interface id
IF_2G4 = '0'
IF_868 = '1'

# User DLT config
LINKTYPE_IEEE802_15_4_WITHFCS = 195
LINKTYPE_IEEE802_15_4_NONASK_PHY = 215
LINKTYPE_IEEE802_15_4_NOFCS = 230
USER_LINKTYPE = LINKTYPE_IEEE802_15_4_WITHFCS

# Maximum payload size for 802.15.4
LINKTYPE_IEEE802_15_4_MAX_LEN = 127

# Lookup table for 802.15.4g payload
whitening_lookup_table = [
    0x00, 0x80, 0x40, 0xC0, 0x20, 0xA0, 0x60, 0xE0, 0x10, 0x90, 0x50, 0xD0, 0x30, 0xB0, 0x70, 0xF0,
    0x08, 0x88, 0x48, 0xC8, 0x28, 0xA8, 0x68, 0xE8, 0x18, 0x98, 0x58, 0xD8, 0x38, 0xB8, 0x78, 0xF8,
    0x04, 0x84, 0x44, 0xC4, 0x24, 0xA4, 0x64, 0xE4, 0x14, 0x94, 0x54, 0xD4, 0x34, 0xB4, 0x74, 0xF4,
    0x0C, 0x8C, 0x4C, 0xCC, 0x2C, 0xAC, 0x6C, 0xEC, 0x1C, 0x9C, 0x5C, 0xDC, 0x3C, 0xBC, 0x7C, 0xFC,
    0x02, 0x82, 0x42, 0xC2, 0x22, 0xA2, 0x62, 0xE2, 0x12, 0x92, 0x52, 0xD2, 0x32, 0xB2, 0x72, 0xF2,
    0x0A, 0x8A, 0x4A, 0xCA, 0x2A, 0xAA, 0x6A, 0xEA, 0x1A, 0x9A, 0x5A, 0xDA, 0x3A, 0xBA, 0x7A, 0xFA,
    0x06, 0x86, 0x46, 0xC6, 0x26, 0xA6, 0x66, 0xE6, 0x16, 0x96, 0x56, 0xD6, 0x36, 0xB6, 0x76, 0xF6,
    0x0E, 0x8E, 0x4E, 0xCE, 0x2E, 0xAE, 0x6E, 0xEE, 0x1E, 0x9E, 0x5E, 0xDE, 0x3E, 0xBE, 0x7E, 0xFE,
    0x01, 0x81, 0x41, 0xC1, 0x21, 0xA1, 0x61, 0xE1, 0x11, 0x91, 0x51, 0xD1, 0x31, 0xB1, 0x71, 0xF1,
    0x09, 0x89, 0x49, 0xC9, 0x29, 0xA9, 0x69, 0xE9, 0x19, 0x99, 0x59, 0xD9, 0x39, 0xB9, 0x79, 0xF9,
    0x05, 0x85, 0x45, 0xC5, 0x25, 0xA5, 0x65, 0xE5, 0x15, 0x95, 0x55, 0xD5, 0x35, 0xB5, 0x75, 0xF5,
    0x0D, 0x8D, 0x4D, 0xCD, 0x2D, 0xAD, 0x6D, 0xED, 0x1D, 0x9D, 0x5D, 0xDD, 0x3D, 0xBD, 0x7D, 0xFD,
    0x03, 0x83, 0x43, 0xC3, 0x23, 0xA3, 0x63, 0xE3, 0x13, 0x93, 0x53, 0xD3, 0x33, 0xB3, 0x73, 0xF3,
    0x0B, 0x8B, 0x4B, 0xCB, 0x2B, 0xAB, 0x6B, 0xEB, 0x1B, 0x9B, 0x5B, 0xDB, 0x3B, 0xBB, 0x7B, 0xFB,
    0x07, 0x87, 0x47, 0xC7, 0x27, 0xA7, 0x67, 0xE7, 0x17, 0x97, 0x57, 0xD7, 0x37, 0xB7, 0x77, 0xF7,
    0x0F, 0x8F, 0x4F, 0xCF, 0x2F, 0xAF, 0x6F, 0xEF, 0x1F, 0x9F, 0x5F, 0xDF, 0x3F, 0xBF, 0x7F, 0xFF
]

# Logger handler
logger = logging.getLogger(__file__)


class ArgumentParser(argparse.ArgumentParser):
    def _get_action_from_name(self, name):
        container = self._actions
        if name is None:
            return None
        for action in container:
            if '/'.join(action.option_strings) == name:
                return action
            elif action.metavar == name:
                return action
            elif action.dest == name:
                return action

    def error(self, message):
        exc = sys.exc_info()[1]
        if exc:
            exc.argument = self._get_action_from_name(exc.argument_name)
            raise exc
        super(ArgumentParser, self).error(message)

"""
Extcap helper methods
"""

def get_serial_ports():
    ports = serial.tools.list_ports.comports()
    return([port.device for port in ports])

def get_freq_from_channel(cfg_id, channel):
    if cfg_id == rfDriver.PHY_CC1352_2G4_802_15_4_O_QPSK:   # Case IEEE 802.15.4, 2.4 GHz
        target_freq = rfDriver.PHY_2G4_802_15_4_O_QPSK_CH_BASE_MHZ
        if channel in range(11, 27):
            target_freq += (channel - 11) * rfDriver.PHY_2G4_802_15_4_O_QPSK_CH_BW_MHZ
            return target_freq
    elif cfg_id == rfDriver.PHY_CC1352_868_802_15_4GE_100_KBPS: # Case IEEE 802.15.4, 868 GHz
        target_freq = rfDriver.PHY_868_802_15_4GE_100_KBPS_CH_BASE_MHZ
        if channel in range(0, 49):
            target_freq += channel * rfDriver.PHY_868_802_15_4GE_100_KBPS_CH_BW_MHZ
            return target_freq
    return None

def check_ch_cfg(cfg_id, channel):
    if cfg_id == rfDriver.PHY_CC1352_868_802_15_4GE_100_KBPS:
        if channel > 49:
            return False
    elif cfg_id == rfDriver.PHY_CC1352_2G4_802_15_4_O_QPSK:
        if channel < 11:
            return False
        elif channel > 26:
            return False
    else:
        return False
    return True

def get_data_802_15_4g(white_frame):
    data_frame = bytearray()
    for byte in white_frame[2:]:
        data_frame += struct.pack('B', whitening_lookup_table[byte])
    return data_frame

def get_data_802_15_4(raw_frame):
    return raw_frame[1:]

"""
Extcap config section
"""

def extcap_config(interface, option):
    args = []
    values = []

    args.append((0, '--serial-port', 'Serial Port', 'Serial port interface', 'selector', '{reload=true}{placeholder=SCAN}'))

    if interface == IF_2G4:
        args.append((1, '--rf-channel', 'RF Channel', 'RF Radio Channel', 'integer', '{range=11,26}{default=11}{required=true}'))
    elif interface == IF_868:
        args.append((1, '--rf-channel', 'RF Channel', 'RF Radio Channel', 'integer', '{range=0,48}{default=0}{required=true}'))

    if option == "serial-port":
        ser_ports = get_serial_ports()
        if len(ser_ports) > 0:
            for index in range(len(ser_ports)):
                values.append((0, ser_ports[index], ser_ports[index], "false"))
        else:
            values.append((0, "None", "", "false"))

    if len(option) <= 0:
        for arg in args:
            logger.info("arg {number=%d}{call=%s}{display=%s}{tooltip=%s}{type=%s}%s" % arg)

        ser_ports = get_serial_ports()
        for index in range(len(ser_ports)):
            values.append((0, ser_ports[index], ser_ports[index], "false"))

    for value in values:
        logger.info("value {arg=%d}{value=%s}{display=%s}{default=%s}" % value)

def extcap_version():
    logger.info("extcap {version=1.0}{help=https://www.wireshark.org}{display=TI Dual-Band interface}")

def extcap_interfaces():
    logger.info("extcap {version=1.0}{help=https://www.wireshark.org}{display=Dual-Band Sniffer Interface}")
    logger.info("interface {value=dbsniff0}{display=IEEE 802.15.4 - O-QPSK - 2405 Mhz}")
    logger.info("interface {value=dbsniff1}{display=IEEE 802.15.4g - GFSK 100 Kpbs - 868 Mhz}")

def extcap_dlts(interface):
    if interface == IF_2G4:
        logger.info("dlt {number=%d}{name=USER0}{display=Extcap IEEE 802.15.4}" % USER_LINKTYPE)
    if interface == IF_868:
        logger.info("dlt {number=%d}{name=USER1}{display=Extcap IEEE 802.15.4g}" % USER_LINKTYPE)

def validate_capture_filter(capture_filter):
    if capture_filter != "filter" and capture_filter != "valid":
        logger.info("Illegal capture filter")

"""
Extcap capture methods
"""

def unsigned(n):
    return int(n) & 0xFFFFFFFF

def pcap_header(dlt_id, max_len):
    header = bytearray()
    header += struct.pack('<L', int('a1b2c3d4', 16))
    header += struct.pack('<H', unsigned(2))            # Pcap Major Version
    header += struct.pack('<H', unsigned(4))            # Pcap Minor Version
    header += struct.pack('<I', int(0))                 # Timezone
    header += struct.pack('<I', int(0))                 # Accuracy of timestamps
    header += struct.pack('<L', max_len)                # Max Length of capture frame
    header += struct.pack('<L', dlt_id)                 # User DLT
    return header

def pcap_packet(rf_payload):
    time_sec = int(time.time())
    time_usec = int((time.time() % 1) * 1000000)
    pcap_header = bytearray()
    pcap_header += struct.pack('<I', time_sec)
    pcap_header += struct.pack('<I', time_usec)
    pcap_header += struct.pack('<I', len(rf_payload))   # number of bytes of packet data that follow this header
    pcap_header += struct.pack('<I', len(rf_payload))   # number of bytes of the packet
    return pcap_header + rf_payload

def extcap_capture(interface, fifo, serial_port, rf_channel):

    rf_config = None
    if interface == IF_2G4:
        rf_config = rfDriver.PHY_CC1352_2G4_802_15_4_O_QPSK
    elif interface == IF_868:
        rf_config = rfDriver.PHY_CC1352_868_802_15_4GE_100_KBPS
    else:
        logger.error("Wrong interface id: %s" % interface)
        sys.exit(ERROR_INTERFACE)

    if rf_channel is None:
        if interface == IF_2G4:
            rf_channel = 11
        elif interface == IF_868:
            rf_channel = 0
        logger.debug("Set default RF channel: %d" % rf_channel)

    if check_ch_cfg(rf_config, rf_channel) != True:
        logger.error("Channel out of range: %d" % rf_channel)
        sys.exit(ERROR_ARG)

    with open(fifo, 'wb', 0) as fh:
        fh.write(pcap_header(USER_LINKTYPE, LINKTYPE_IEEE802_15_4_MAX_LEN))
        logger.debug("Create RF handler")
        sniffer = rfDriver.SmartRfDevice(serial_port)
        if sniffer.ping():
            sniffer.phy(rf_config)
            rf_freq_cfg = get_freq_from_channel(rf_config, rf_channel)
            if rf_freq_cfg != None:
                sniffer.freq(rf_freq_cfg)
                sniffer.start()
                logger.debug("Start capture")
                while True:
                    try:
                        rxData = sniffer.waitData()
                        if rxData != None:
                            if rxData.getStatus() == rfDriver.DATA_STATUS_FCS_OK:
                                pcap_data = None
                                if interface == IF_868:
                                    pcap_data = get_data_802_15_4g(rxData.getData())
                                else:
                                    pcap_data = get_data_802_15_4(rxData.getData())
                                fh.write(pcap_packet(pcap_data))
                    except:
                        logger.exception("Exception during capture")
                        sniffer.close()
                        sys.exit(ERROR_INTERFACE)
            else:
                sniffer.close()
                extcap_close_fifo(fifo)
                logger.error("Not valid freq: %.02f" % rf_freq_cfg)
                sys.exit(ERROR_INTERFACE)

def extcap_close_fifo(fifo):
    fh = open(fifo, 'wb', 0)
    fh.close()


"""
Main code
"""


def logger_config(logger_handler):
    log_filename = os.path.dirname(__file__) + "/extcap.log"

    # Handler for error log file
    fileHandlerFormatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    fileHandler = logging.FileHandler(log_filename)
    fileHandler.setFormatter(fileHandlerFormatter)
    fileHandler.setLevel(logging.DEBUG)

    # Handler for extcap
    wiresharkHandlerFormatter = logging.Formatter("%(message)s")
    wiresharkHandler = logging.StreamHandler(sys.stdout)
    wiresharkHandler.setFormatter(wiresharkHandlerFormatter)
    wiresharkHandler.setLevel(logging.INFO)

    # Handler for errors
    errorHandlerFormatter = logging.Formatter("%(message)s")
    errorHandler = logging.StreamHandler(sys.stderr)
    errorHandler.setFormatter(errorHandlerFormatter)
    errorHandler.setLevel(logging.ERROR)

    logger.addHandler(wiresharkHandler)
    logger.addHandler(errorHandler)
    logger.addHandler(fileHandler) # Comment to disable debug output

    logger.setLevel(logging.DEBUG)
    logger.debug("INIT EXTCAP")

def usage():
    logger.info("Usage: %s <--extcap-interfaces | --extcap-dlts | --extcap-interface | --extcap-config | --capture | --extcap-capture-filter | --fifo>" % sys.argv[0])

if __name__ == '__main__':
    interface = ""
    option = ""
    extcap_serial_port = None
    extcap_rf_channel = 0

    parser = ArgumentParser(
            prog="Extcap Dual-Band Sniffer",
            description="Extcap interface for dual-band custom board"
            )

    # Extcap Arguments
    parser.add_argument("--capture", help="Start the capture routine", action="store_true" )
    parser.add_argument("--extcap-interfaces", help="Provide a list of interfaces to capture from", action="store_true")
    parser.add_argument("--extcap-interface", help="Provide the interface to capture from")
    parser.add_argument("--extcap-dlts", help="Provide a list of dlts for the given interface", action="store_true")
    parser.add_argument("--extcap-config", help="Provide a list of configurations for the given interface", action="store_true")
    parser.add_argument("--extcap-capture-filter", help="Used together with capture to provide a capture filter")
    parser.add_argument("--fifo", help="Use together with capture to provide the fifo to dump data to")
    parser.add_argument("--extcap-control-in", help="Used to get control messages from toolbar")
    parser.add_argument("--extcap-control-out", help="Used to send control messages to toolbar")
    parser.add_argument("--extcap-version", help="Shows the version of this utility", nargs='?', default="")
    parser.add_argument("--extcap-reload-option", help="Reload elements for the given option")

    # Interface Arguments
    parser.add_argument("--serial-port", help="Select serial port", type=str )
    parser.add_argument("--rf-channel", help="Select RF channel", type=int )

    logger_config(logger)
    logger.debug(sys.argv)

    try:
        args, unknown = parser.parse_known_args()
    except argparse.ArgumentError as exc:
        logger.info("%s: %s" % (exc.argument.dest, exc.message), file=sys.stderr)
        fifo_found = 0
        fifo = ""
        for arg in sys.argv:
            if arg == "--fifo" or arg == "--extcap-fifo":
                fifo_found = 1
            elif fifo_found == 1:
                fifo = arg
                break
        extcap_close_fifo(fifo)
        sys.exit(ERROR_ARG)

    # Agparse parameter validation

    if len(sys.argv) <= 1:
        parser.exit("No arguments given!")

    if args.extcap_version and not args.extcap_interfaces:
        extcap_version()
        sys.exit(0)

    if not args.extcap_interfaces and args.extcap_interface is None:
        parser.exit("An interface must be provided or the selection must be displayed")

    if args.extcap_capture_filter and not args.capture:
        validate_capture_filter(args.extcap_capture_filter)
        sys.exit(0)

    if args.extcap_interfaces or args.extcap_interface is None:
        extcap_interfaces()
        sys.exit(0)

    if len(unknown) > 1:
        logger.info("Extcap %d unknown arguments given" % len(unknown))

    m = re.match('dbsniff(\d+)', args.extcap_interface)
    if not m:
        sys.exit(ERROR_INTERFACE)
    interface = m.group(1)

    if args.extcap_reload_option and len(args.extcap_reload_option) > 0:
        option = args.extcap_reload_option

    extcap_serial_port = args.serial_port
    extcap_rf_channel = args.rf_channel

    # Argparse action execution

    if args.extcap_config:
        extcap_config(interface, option)
    elif args.extcap_dlts:
        extcap_dlts(interface)
    elif args.capture:
        if args.fifo is None:
            sys.exit(ERROR_FIFO)
        try:
            extcap_capture(interface, args.fifo, extcap_serial_port, extcap_rf_channel)
        except KeyboardInterrupt:
            pass
    else:
        usage()
        sys.exit(ERROR_USAGE)
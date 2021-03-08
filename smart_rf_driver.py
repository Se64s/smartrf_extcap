#!/usr/bin/env python
""" Module to interface SmartRF Sniffer devices.

Implements a basic subset of commands to handle cc1352r1 devices for 802.15.4 and 802.15.4g physical interfaces (aimed for ZigBee sniffing).

More information about commands and options:
https://software-dl.ti.com/lprf/packet_sniffer_2/docs/user_guide/html/sniffer_fw/firmware/command_interface.html
"""

import serial
import struct
import logging
import os

__author__ = "Sebastián Del Moral"
__copyright__ = ""
__credits__ = ["Sebastián Del Moral"]
__license__ = "MIT License"
__version__ = "0.0.1"
__maintainer__ = "Sebastián Del Moral"
__email__ = "sebmorgal@gmail.com"
__status__ = "Development"

# Serial port parameters
# SER_BAUDRATE = 921600 # SmartRF v1.8.0
SER_BAUDRATE = 3000000 # SmartRF v1.9.0
SER_TIMEOUT = 0.1

# Packet info categories
INFO_CAT_RES = 0
INFO_CAT_CMD = 1
INFO_CAT_RSP = 2
INFO_CAT_DAT = 3

# Defined info cmd values
INFO_CMD_PING = 0x40
INFO_CMD_START = 0x41
INFO_CMD_STOP = 0x42
INFO_CMD_PAUSE = 0x43
INFO_CMD_RESUME = 0x44
INFO_CMD_CFG_FREQ = 0x45
INFO_CMD_CFG_PHY = 0x47

# Defined info data
INFO_DATA = 0xC0
INFO_ERROR = 0xC1

# Defined data status
DATA_STATUS_FCS_OK = 0x80
DATA_STATUS_FCS_BAD = 0x00

# Defined valid PHY index
PHY_CC1352_868_802_15_4GE_100_KBPS = 0x09
PHY_CC1352_2G4_802_15_4_O_QPSK = 0x0D

# Response status
RSP_STATUS_OK = 0
RSP_STATUS_TIMEOUT = 1
RSP_STATUS_FCS_ERR = 2
RSP_STATUS_INVALID_CMD = 3
RSP_STATUS_INVALID_STATE = 4

# Usefull freq
PHY_2G4_802_15_4_O_QPSK_CH_BASE_MHZ = 2405.0
PHY_2G4_802_15_4_O_QPSK_CH_BW_MHZ = 5.0

PHY_868_802_15_4GE_100_KBPS_CH_BASE_MHZ = 863.25
PHY_868_802_15_4GE_100_KBPS_CH_BW_MHZ = 0.2

# Logger options
log_filename = os.path.dirname(__file__) + "/rfDriver.log"
logger = logging.getLogger(__file__)
logger.setLevel(logging.DEBUG)

fileHandlerFormatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
fileHandler = logging.FileHandler(log_filename)
fileHandler.setFormatter(fileHandlerFormatter)
fileHandler.setLevel(logging.INFO)

# Comment to disable file logging
logger.addHandler(fileHandler)

class RadioFrame:

    """
    Class for handling radio payload
    """

    def __init__(self, payload=None):
        self.timestamp = 0
        self.data = bytearray()
        self.rssi = 0
        self.status = 0
        if len(payload) >= 8:
            self.timestamp = 0
            self.timestamp |= payload[0] << 0
            self.timestamp |= payload[1] << 8
            self.timestamp |= payload[2] << 16
            self.timestamp |= payload[3] << 32
            self.timestamp |= payload[4] << 40
            self.timestamp |= payload[5] << 48
            self.data = payload[6:-2]
            self.rssi = payload[-2]
            self.status = payload[-1]

    def getTimestamp(self):
        return self.timestamp

    def getData(self):
        return self.data

    def getRssi(self):
        return self.rssi

    def getStatus(self):
        return self.status


class SerialFrame:

    """
    Class for handling serial frames
    """

    def __init__(self, info, payload=bytearray()):
        self.info = info
        self.len = len(payload)
        self.payload = payload
        self.fcs = None
        # Check if FCS
        info_cat = (self.info >> 6) & 0x03
        if (info_cat == INFO_CAT_CMD) or (info_cat == INFO_CAT_RSP):
            self.fcs = 0
            self.fcs += info
            self.fcs += (self.len >> 0) & 0xFF
            self.fcs += (self.len >> 8) & 0xFF
            for byte in self.payload:
                self.fcs += byte
            self.fcs &= 0xFF

    def getFCS(self):
        return self.fcs

    def getInfo(self):
        return self.info

    def getInfoCat(self):
        return (self.info >> 6) & 0x03

    def getInfoType(self):
        return self.info & 0x3F

    def getPayload(self):
        return self.payload

    def getPayloadLen(self):
        return self.len

    def getFrame(self):
        frame = bytearray()
        frame += struct.pack('<H', int('5340', 16))
        frame += struct.pack('B', self.info)
        frame += struct.pack('<H', self.len)
        frame += self.payload
        if self.fcs != None:
            frame += struct.pack('B', self.fcs)
        frame += struct.pack('<H', int('4540', 16))
        return frame


class SmartRfDevice:

    """
    Class for handling serial comunication
    """

    def __init__(self, serial_port=None):
        # Setup error log
        logger.info("INIT RF Driver - log: %s" % log_filename)
        self.dev = serial.Serial()
        self.dev.port = serial_port
        self.dev.baudrate = SER_BAUDRATE
        self.dev.timeout = SER_TIMEOUT
        if serial_port != None:
            self.open()

    def __del__(self): 
        if self.dev.is_open:
            logger.info("CLEANUP serial port")
            self.dev.close()

    def open(self, serial_port=None):
        if self.dev.isOpen():
            self.dev.close()
        if serial_port != None:
            self.dev.port = serial_port
        logger.info("OPEN serial port")
        self.dev.open()
        self.stop()

    def close(self):
        logger.info("CLOSE serial port")
        self.dev.close()

    def ping(self):
        txFrame = SerialFrame(info=INFO_CMD_PING)
        self.__sendFrame(txFrame)
        rxFrame = self.__waitFrame()
        if (rxFrame != None) and (rxFrame.getInfoCat() == INFO_CAT_RSP):
            rxPayload = rxFrame.getPayload()
            rxData = struct.unpack('<BHBBH', rxPayload)
            logger.info("PING: Status: x%02X, HwId: x%04X, HwRev: x%02X, FwId: x%02X, FwRev: x%04X" % rxData)
            if rxData[0] == RSP_STATUS_OK:
                return True
        return False

    def freq(self, FreqMhz):
        logger.info("FRQ: FreqMhz %.02f" % FreqMhz)
        baseFreq = int(FreqMhz)
        fractFreq = int((FreqMhz % 1) * 0xFFFF)
        cmdPayload = bytearray()
        cmdPayload += struct.pack('<H', baseFreq)
        cmdPayload += struct.pack('<H', fractFreq)
        txFrame = SerialFrame(info=INFO_CMD_CFG_FREQ, payload=cmdPayload)
        self.__sendFrame(txFrame)
        rxFrame = self.__waitFrame()
        if (rxFrame != None) and (rxFrame.getInfoCat() == INFO_CAT_RSP):
            rxPayload = rxFrame.getPayload()
            rxData = struct.unpack('B', rxPayload)
            logger.info("FRQ: Status: x%02X" % rxData)
            if rxData[0] == RSP_STATUS_OK:
                return True
        return False

    def phy(self, phy):
        logger.info("PHY: phy: x%02X" % phy)
        if phy in [PHY_CC1352_868_802_15_4GE_100_KBPS, PHY_CC1352_2G4_802_15_4_O_QPSK]:
            cmdPayload = bytearray()
            cmdPayload += struct.pack('B', phy)
            txFrame = SerialFrame(info=INFO_CMD_CFG_PHY, payload=cmdPayload)
            self.__sendFrame(txFrame)
            rxFrame = self.__waitFrame()
            if (rxFrame != None) and (rxFrame.getInfoCat() == INFO_CAT_RSP):
                rxPayload = rxFrame.getPayload()
                rxData = struct.unpack('B', rxPayload)
                logger.info("PHY: Status: x%02X" % rxData)
                if rxData[0] == RSP_STATUS_OK:
                    return True
        else:
            logger.error("PHY: %d out of range" % phy)
        return False

    def start(self):
        logger.info("START")
        txFrame = SerialFrame(info=INFO_CMD_START)
        self.__sendFrame(txFrame)
        rxFrame = self.__waitFrame()
        if (rxFrame != None) and (rxFrame.getInfoCat() == INFO_CAT_RSP):
            rxPayload = rxFrame.getPayload()
            rxData = struct.unpack('B', rxPayload)
            logger.info("START: Status: x%02X" % rxData)
            if rxData[0] == RSP_STATUS_OK:
                return True
        return False

    def stop(self):
        logger.info("STOP")
        txFrame = SerialFrame(info=INFO_CMD_STOP)
        self.__sendFrame(txFrame)
        rxFrame = self.__waitFrame()
        if (rxFrame != None) and (rxFrame.getInfoCat() == INFO_CAT_RSP):
            rxPayload = rxFrame.getPayload()
            rxData = struct.unpack('B', rxPayload)
            logger.info("STOP: Status: x%02X" % rxData)
            if rxData[0] == RSP_STATUS_OK:
                return True
        return False

    def waitData(self):
        rxFrame = self.__waitFrame()
        if (rxFrame != None) and (rxFrame.getInfo() == INFO_DATA):
            rfData = RadioFrame(rxFrame.getPayload())
            dbgStr = 'RF DATA: timestamp %d, rssi %d, status %d, len %d, data ' % (rfData.getTimestamp(), rfData.getRssi(), rfData.getStatus(), len(rfData.getData()))
            for byte in rfData.getData():
                dbgStr += 'x%02X ' % byte
            logger.debug(dbgStr)
            return rfData
        return None

    def pause(self):
        logger.info("PAUSE")
        txFrame = SerialFrame(info=INFO_CMD_PAUSE)
        self.__sendFrame(txFrame)
        rxFrame = self.__waitFrame()
        if (rxFrame != None) and (rxFrame.getInfoCat() == INFO_CAT_RSP):
            rxPayload = rxFrame.getPayload()
            rxData = struct.unpack('B', rxPayload)
            logger.info("PAUSE: Status: x%02X" % rxData)
            if rxData[0] == RSP_STATUS_OK:
                return True
        return False

    def __sendFrame(self, frame):
        txData = frame.getFrame()
        dbgStr = 'RAW_TX: '
        for byte in txData:
            dbgStr += 'x%02X ' % byte
        logger.debug(dbgStr)
        self.dev.write(txData)

    def __waitFrame(self):
        # Get SOF
        rxData = self.dev.read(1)
        if len(rxData) == 1:
            if (rxData[0] == 0x40):
                rxData = self.dev.read(1)
                if len(rxData) == 1:
                    if (rxData[0] == 0x53):
                        rxData = self.dev.read(3)
                        if len(rxData) == 3:
                            infoData = rxData[0]
                            lenData = rxData[1] | (rxData[2] << 8)
                            rxPayload = self.dev.read(lenData)
                            if len(rxPayload) == lenData:
                                fcsData = None
                                infoCat = infoData >> 6
                                if (infoCat == INFO_CAT_CMD) or (infoCat == INFO_CAT_RSP):
                                    rxData = self.dev.read(1)
                                    if len(rxData) == 1:
                                        fcsData = rxData[0]
                                # Get EOF
                                rxData = self.dev.read(2)
                                if len(rxData) == 2:
                                    if (rxData[0] == 0x40) and (rxData[1] == 0x45):
                                        rxFrame = SerialFrame(infoData, rxPayload)
                                        if fcsData == rxFrame.getFCS():
                                            # RX DBG
                                            frameData = rxFrame.getFrame()
                                            dbgStr = 'RAW_RX: '
                                            for byte in frameData:
                                                dbgStr += 'x%02X ' % byte
                                            logger.debug(dbgStr)
                                            return rxFrame
        return None


def main():

    """
    Test program
    """

    test_port = 'COM17'
    sniffer = SmartRfDevice(test_port)
    rf_ch = 11
    rf_ch_offset = 11
    ch_index = rf_ch - rf_ch_offset
    sniffer.open()
    if sniffer.ping():
        sniffer.phy(PHY_CC1352_2G4_802_15_4_O_QPSK)
        sniffer.freq(PHY_2G4_802_15_4_O_QPSK_CH_BASE_MHZ + PHY_2G4_802_15_4_O_QPSK_CH_BW_MHZ * ch_index)
        sniffer.start()
        count=0
        while True:
            rxData = sniffer.waitData()
            if rxData != None:
                print("RX: ", end='')
                for byte in rxData.getData():
                    print("x%02X " % byte, end='')
                print("")
                count += 1
                if count == 10:
                    break
        sniffer.close()

if __name__ == "__main__":
    main()
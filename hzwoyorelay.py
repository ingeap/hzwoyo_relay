#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# 2019.12.14 IAP 
# 
# Usage: ./hzwoyorelay.py -i 192.168.1.110 -r 7
#
# #

'''

Setup: http://192.168.1.110/sernet1cn.shtml?2
        Select UDP server

Product: http://hzwoyo.com/product-detail/eth8io30a/
        Manufacturer: Hangzhou Woyao Intelligent Control Technology Co., Ltd.


Info from http://hzwoyo.com/support/:

        Modified address: The
        example is modified to 00100101
        55 AA AA AA AA AA 01 09 04 00 00 00 00 00 10 01 01 C7 16 The
        example is modified to 00100102
        55 AA AA AA AA AA 01 09 04 00 00 00 00 00 10 01 02 C8 16 The
        example is modified to: 00100103
        55 AA AA AA AA AA 01 09 04 00 00 00 00 00 10 01 03 C9 16
        Single-way jog instruction:
        =============
        Device address: 00100101
        No. 1 Jog
        55 00 10 01 01 AA 03 06 90 00 00 00 00 01 AB 16
        55 00 10 01 01 AA 03 06 90 00 00 00 00 02 AC 16
        2nd jog
        55 00 10 01 01 AA 03 06 91 00 00 00 00 01 AC 16
        55 00 10 01 01 AA 03 06 91 00 00 00 00 02 AD 16
        3rd jog
        55 00 10 01 01 AA 03 06 92 00 00 00 00 AD 16
        55 00 10 01 01 AA 03 06 92 00 00 00 00 02 AE 16
        Jog 4
        55 00 10 01 01 AA 03 06 93 00 00 00 00 01 AE 16
        55 00 10 01 01 AA 03 06 93 00 00 00 00 02 AF 16

        ———————————————————————————
        Equipment address: 00100102 Jog
        No. 1 of the road
        55 00 10 01 02 AA 03 06 90 00 00 00 00 01 AC 16
        55 00 10 01 02 AA 03 06 90 00 00 00 00 02 AD 16
        2nd jog
        55 00 10 01 02 AA 03 06 91 00 00 00 00 01 AD 16
        55 00 10 01 02 AA 03 06 91 00 00 00 00 02 AE 16
        3rd jog
        55 00 10 01 02 AA 03 06 92 00 00 00 00 01 AE 16
        55 00 10 01 02 AA 03 06 92 00 00 00 00 02 AF 16
        4th jog
        55 00 10 01 02 AA 03 06 93 00 00 00 00 01 AF 16
        55 00 10 01 02 AA 03 06 93 00 00 00 00 02 B0 16

        ———————————————————————————-
        Equipment address: 00100103 Jog
        No. 1 of the road
        55 00 10 01 03 AA 03 06 90 00 00 00 00 01 AD 16
        55 00 10 01 03 AA 03 06 90 00 00 00 00 02 AE 16
        2nd Jog
        55 00 10 01 03 AA 03 06 91 00 00 00 00 01 AE 16
        55 00 10 01 03 AA 03 06 91 00 00 00 00 02 AF 16
        third jog
        55 00 10 01 03 AA 03 06 92 00 00 00 00 01 AF 16
        55 00 10 01 03 AA 03 06 92 00 00 00 00 02 B0 16
        fourth jog
        55 00 10 01 03 AA 03 06 93 00 00 00 00 01 B0 16
        55 00 10 01 03 AA 03 06 93 00 00 00 00 02 B1 16

        1 2 3 4-way suction and disconnection in one second
        =========================
        Device address: 00100101
        55 00 10 01 01 AA 03 11 9F 00 00 00 00 01 01 01 01 FF FF FF FF FF FF FF FF C0 16
        55 00 10 01 01 AA 03 11 9F 00 00 00 00 02 02 02 FF FF FF FF FF FF FF FF C4 16
        ——————— ——————————————————————-
        Device address: 00100102
        55 00 10 01 02 AA 03 11 9F 00 00 00 00 01 01 01 01 FF FF FF FF FF FF FF FF C1 16
        55 00 10 01 02 AA 03 11 9F 00 00 00 00 02 02 02 02 FF FF FF FF FF FF FF FF C5 16
        ————————————————————— ——————-
        Device address: 00100103
        55 00 10 01 03 AA 03 11 9F 00 00 00 00 01 01 01 01 FF FF FF FF FF FF FF FF C2 16
        55 00 10 01 03 AA 03 11 9F 00 00 00 00 02 02 02 02 FF FF FF FF FF FF FF FF C6 16
        —————————————————————————
        1-2 jog instructions:
        ==============
        Device address: 00100101
        55 00 10 01 01 AA 03 11 9F 00 00 00 00 01 01 FF FF FF FF FF FF FF FF FF FF BC 16
        55 00 10 01 01 AA 03 11 9F 00 00 00 00 02 02 FF FF FF FF FF FF FF FF FF FF BE 16
        —————————————————————————-
        Device address ： 00100102
        55 00 10 01 02 AA 03 11 9F 00 00 00 00 01 01 FF FF FF FF FF FF FF FF FF FF BD 16
        55 00 10 01 02 AA 03 11 9F 00 00 00 00 02 02 FF FF FF FF FF FF FF FF FF FF BF 16
        ———————————————————————————
        Device address: 00100103
        55 00 10 01 03 AA 03 11 9F 00 00 00 00 01 01 FF FF FF FF FF FF FF FF FF FF BE 16
        55 00 10 01 03 AA 03 11 9F 00 00 00 00 02 02 FF FF FF FF FF FF FF FF FF FF C0 16
        ———————— ———————————————————-
        3-4 Jog instruction:
        ============
        Device address: 00100101
        55 00 10 01 01 AA 03 11 9F 00 00 00 00 FF FF 01 01 FF FF FF FF FF FF FF BC 16
        55 00 10 01 01 AA 03 11 9F 00 00 00 00 FF FF 02 02 FF FF FF FF FF FF FF FF BE 16
        ———————————————————————————-
        Device address: 00100102
        55 00 10 01 02 AA 03 11 9F 00 00 00 00 FF FF 01 01 FF FF FF FF FF FF FF FF BD 16
        55 00 10 01 02 AA 03 11 9F 00 00 00 00 FF FF 02 02 FF FF FF FF FF FF FF FF BF BF 16
        ---------- ———————————————————————
        Device address: 00100103
        55 00 10 01 03 AA 03 11 9F 00 00 00 00 FF FF 01 01 FF FF FF FF FF FF FF FF BE 16
        55 00 10 01 03 AA 03 11 9F 00 00 00 00 FF FF 02 02 FF FF FF FF FF FF FF FF C0 16

        1-3 Jog instruction:
        =============
        device address: 00100101
        55 00 10 01 01 AA 03 11 9F 00 00 00 00 01 FF 01 FF FF FF FF FF FF FF FF FF BC 16
        55 00 10 01 01 AA 03 11 9F 00 00 00 00 02 FF 02 FF FF FF FF FF FF FF FF FF BE 16
        ——————————————————————— ————-
        Device address: 00100102
        55 00 10 01 02 AA 03 11 9F 00 00 00 00 01 FF 01 FF FF FF FF FF FF FF FF FF BD 16
        55 00 10 01 02 AA 03 11 9F 00 00 00 00 02 FF 02 FF FF FF FF FF FF FF FF FF BF BF 16
        —————————————————————————
        Device address: 00100103
        55 00 10 01 03 AA 03 11 9F 00 00 00 00 01 FF 01 FF FF FF FF FF FF FF FF FF BE 16
        55 00 10 01 03 AA 03 11 9F 00 00 00 00 02 FF 02 FF FF FF FF FF FF FF FF FF C0 16

        2-4 Jog instruction:
        =============
        Device address: 00100101
        55 00 10 01 01 AA 03 11 9F 00 00 00 00 FF 01 FF 01 FF FF FF FF FF FF FF FF FF 16
        55 00 10 01 01 AA 03 11 9F 00 00 00 00 FF 02 FF 02 FF FF FF FF FF FF FF FF BE 16
        ——————————————————————— ————-
        Device address: 00100102
        55 00 10 01 02 AA 03 11 9F 00 00 00 00 FF 01 FF 01 FF FF FF FF FF FF FF FF BD 16
        55 00 10 01 02 AA 03 11 9F 00 00 00 00 FF 02 FF 02 FF FF FF FF FF FF FF FF FF BF 16
        —————————————————————————-
        Device address: 00100103
        55 00 10 01 03 AA 03 11 9F 00 00 00 00 FF 01 FF 01 FF FF FF FF FF FF FF FF BE 16
        55 00 10 01 03 AA 03 11 9F 00 00 00 00 FF 02 FF 02 FF FF FF FF FF FF FF FF C0 16

        The network relay dynamic library is compiled and exported with VC ++, which can be run on the Microsoft operating system platform, supports multiple language calls, and the
        function supports encoding and decoding 2 function interfaces:

        1. Encoding function
        Read 00H
        str_Address device address (4 bytes, aa aa aa aa is the super address)
        str_Flag identification code (1 byte, identifying the read content)

        Private Declare Function RelayRead Lib “RelayCtl.dll” (ByVal str_Address As String, ByVal str_Flag As String) As String

        Write
        str_Address device address (4 bytes, aa aa aa aa is super address)
        str_Ctrl control code 01H, 02H, 03H, 08H
        str_Flag identification code (1 byte, identification read content)
        str_Pass password (empty default is default 0)
        Private Declare Function RelayWrite Lib “RelayCtl.dll” (ByVal str_Address As String, ByVal str_Ctrl As String, ByVal str_Flag As String, ByVal str_Pass As String) As String

        2.
        The uplink data frame received by the decoding function str_Frame
        will return the device address, control code, identification code, and data area
        Private Declare Function RelayDec Lib “RelayCtl.dll” (ByVal str_Frame As String, ByVal str_Ctrl As String, ByVal str_Flag As String) ) As String
        3. Usage The
        user must first connect to the controller through TCP, and directly call the RelayRead or RelayWrite function to generate a HEX format ASCII character command string when sending data, and directly send it to the specified control IP.
        The received protocol frame directly calls the RelayDec function for decoding. After decoding, the device address, control code, identification code, and data area are returned, and then judged based on the corresponding data.

'''

import socket
import optparse
import sys
import struct
import binascii


class UDPClient:
    def __init__(self,addr,port):
        
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    #	self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s.settimeout(2)
        self.s.bind((addr,port))
    def rx(self,append_id=True):		
        data,addr = self.s.recvfrom(1024)		
        return (data,addr)
    
    def close(self):
        self.s.close()


def make_packet(addr, ctrl, cmd, data):

    # 5500000000aa
    # 00000000 addresse adresse=aaaaaaaa = broadcast?

    packet = struct.pack(">BBBBBBBBB",
        0x55,
        (addr>>(8*3))&0xff,
        (addr>>(8*2))&0xff,
        (addr>>(8*1))&0xff,
        (addr>>(8*0))&0xff,
        0xaa,
        ctrl,
        len(data)+1,
        cmd
    )

    packet += data

    #crc
    crc = 0
    for c in packet:
        crc += c

    packet += struct.pack(">BB", (crc & 0xff), 0x16)

    return packet


def pulse_relay(nr, duration):

    if (nr < 0) or (nr > 7):
        print("Invalid relay nr")
        return None

    if (duration < 0) or (duration > 0xef):
        print("Invalid duration")
        return None

    cmd = 0x90 | nr

    return make_packet(0x00000000, 0x03,cmd, struct.pack(">BBBBB", 0,0,0,0, duration))

        
if __name__ == "__main__":
    
    parser = optparse.OptionParser(usage="./kinarele.py -i 192.168.1.110 -r 7")
    parser.add_option("-p", action="store", dest="port" , default=6000, type="int", help="Listen port")
    parser.add_option("-i", action="store", dest="ip" , default="", help="Destination IP")
    parser.add_option("-r", action="store", dest="relay" , default=0, type="int", help="Relay nr 0-7")
    parser.add_option("-d", action="store", dest="duration" , default=5, type="int", help="Pulse duration")
    (options, args) = parser.parse_args()

    udp_client = UDPClient("",options.port)

    for retry in range(0,3):
    
        # Make packet and send
        data = pulse_relay(options.relay, options.duration)
        udp_client.s.sendto(data, (options.ip, 8899))
        
        sys.stdout.write(binascii.hexlify(data).decode("ascii")+"    ")

        # Receive response
        try:
            (data,(cre_ip,cre_port)) = udp_client.rx()

            sys.stdout.write(str(cre_ip)+" "+str(cre_port)+" ")        

            sys.stdout.write(binascii.hexlify(data).decode("ascii"))

            if binascii.hexlify(data) == "5500000000aac00102c216":
                sys.stdout.write(" ERR")
            else:
                break
            
        except:
            sys.stdout.write("RX TIMEOUT") 
            

        sys.stdout.write("\r\n")
        sys.stdout.flush()

    sys.stdout.write("\r\n")
    sys.stdout.flush()


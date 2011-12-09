#!/usr/bin/python
from crcISO import crc16_iso14443a
from binascii import hexlify, unhexlify 
from loyalty_card import bytes_to_hexstr, hexstr_to_bytes
from crypto import decipher_CBC_send_mode
from Crypto.Cipher import DES, DES3

def data_input():
    return ''.join([x for x in raw_input() if x in "0123456789ABCDEFabcdef"])

def hexstr2bytelist(hex_str):
    """converts a string of hexadecimal characters to a list of bytes
    since 2 hex make one byte, len(str) must be even"""
    if len(hex_str) % 2 != 0:
        raise ValueError('hexstring ({}) has odd length'.format(hexstring))

    bytel = []
    for i in xrange(0, len(hex_str), 2):
        bytel.append(int(hex_str[i], 16) * 16 + int(hex_str[i+1], 16))

    return bytel


def main():
    print "enter the current session key or press <enter> for default"
    curmaink = unhexlify("00"*8)
    nt = unhexlify("cb06b4f59a82f6f0")
    nr = unhexlify("aabbccddeeff1122")
    if curmaink[0:len(curmaink)/2] == curmaink[len(curmaink)/2:len(curmaink)]:
        autocurrentk = nr[0:4] + nt[0:4]
    else:
        autocurrentk = (nr[0:4] + nt[0:4] + nr[4:8] + nt[4:8])
    currentk = data_input() 
    currentk = currentk != "" and unhexlify(currentk) or autocurrentk
    print len(currentk)
    if not (len(currentk) == 8 or len(currentk) == 16):
        raise ValueError("current key size must be either 8bytes (DES) or 16bytes (3DES)")

    print "enter a new 16-byte key or press <enter> for default"
    k3des_str = data_input() or "11223344556677889900AABBCCDDEEFF"
    if len(k3des_str) != 16*2:
        raise ValueError("length of the key must be 16 bytes")

    k3des_bytel = hexstr_to_bytes(k3des_str)
    crc = crc16_iso14443a(k3des_bytel)
    data = unhexlify(bytes_to_hexstr(k3des_bytel + crc + [0, 0, 0, 0, 0, 0]))
    print hexlify(decipher_CBC_send_mode(currentk, data, 
        len(currentk) == 8 and DES or DES3))

if __name__ == "__main__":
    main()

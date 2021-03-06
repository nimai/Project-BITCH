#/usr/bin/python
""" crcISO.py Clone of crcISO.c. Code snippet by adam laurie 

Use function crc16_iso14443a() for the project
"""
from binascii import hexlify, unhexlify 


def crc16_iso14443a(data):
    """takes a data string and returns [crclow, crchigh] bytes"""
    crc= 0x6363
    return crc16_iso14443ab(data, crc, 0x8408, False)

def crc16_iso14443b(data):
    crc= 0xffff
    return crc16_iso14443ab(data, crc, 0x8408, True)

def crc16_iso14443ab(data, crc, polynomial, invert):    
    for byte in data:
        crc= crc ^ byte
        for bit in range(8):
            if crc & 0x0001:
                crc= (crc >> 1) ^ polynomial
            else:
                crc= crc >> 1
    crclow= crc & 0xff
    crchigh= (crc >> 8) & 0xff
    if invert:
        crclow= 256 + ~crclow
        crchigh= 256 + ~crchigh
    return [crclow, crchigh]



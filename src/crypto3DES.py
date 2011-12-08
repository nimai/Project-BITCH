''' Utility functions for doing crypto stuff '''

#from pycryptopp import *
from Crypto.Cipher import DES33
from Crypto.Random.random import *
from crcISO import *

import Crypto.Random.random
import struct

def perform_authentication(key, cipher_text):
    iv = unhexlify("00"*8)
    #a
    des = DES3.new(key, DES3.MODE_CBC, iv) 
    nt = des.decrypt(cipher_text)       
    nt2 = nt[1:]+nt[:1]    
    # b        
    des = DES3.new(key, DES3.MODE_CBC, iv)
    # 20 = ceil(log(2**64-1)/log(10))
    nr=unhexlify(str(StrongRandom().randint(0,2**64-1)).zfill(20,"0"))        
    D1=des.decrypt(nr)      
    #c
    longlongint1=struct.unpack('>Q',struct.pack('8s', D1))[0]
    longlongint2=struct.unpack('>Q',struct.pack('8s', nt2))[0]
    buff=struct.unpack('8s',struct.pack('>Q', longlongint1 ^ longlongint2))[0]     
    # d
    des = DES3.new(key, DES3.MODE_CBC, iv)
    D2=des.decrypt(buff)    
    #e		
    return nt, nt2, nr, D1, D2  

def xor(a,b):
    longlongint1=struct.unpack('>Q',struct.pack('8s', a))[0]
    longlongint2=struct.unpack('>Q',struct.pack('8s', b))[0]
    buff=struct.unpack('8s',struct.pack('>Q', longlongint1 ^ longlongint2))[0]  
    return buff

def decipher_CBC_send_mode(session_key, data):
    res = ""
    iv = unhexlify("00"*8)
    des = DES3.new(session_key, DES3.MODE_CBC, iv)
    d = des.decrypt(data[0:8])
    res+=d
    i=8
    while not i == len(data):
        des = DES3.new(session_key, DES3.MODE_CBC, iv)  
        d = des.decrypt(xor(d, data[i:i+8])) 
        res+=d
        i+=8    
    return res

def decipher_CBC_receive_mode(session_key, data):
    iv = unhexlify("00"*8)
    des = DES3.new(session_key, DES3.MODE_CBC, iv)
    return des.decrypt(data)

def encipher_DES3(mode, iv, key, data):
    des = DES3.new(session_key, mode, iv)
    return des.encrypt(data)

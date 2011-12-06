''' Utility functions for doing crypto stuff '''

#from pycryptopp import *
from Crypto.Cipher import DES
from Crypto.Random.random import *
from crcISO import *
from M2Crypto import *

import Crypto.PublicKey.RSA as pyRSA
import Crypto.Random.random
import Crypto.Hash.SHA as SHA
import base64
import struct

def long_to_hexstr(n):
    return hexlify(unhexlify("%x" % n)) 

def hexstr_to_long(s):
    return long(s, 16)

def perform_authentication(key, cipher_text):
    iv = unhexlify("00"*8)
    #a
    des = DES.new(key, DES.MODE_CBC, iv) 
    nt = des.decrypt(cipher_text)       
    nt2 = nt[1:]+nt[:1]    
    # b        
    des = DES.new(key, DES.MODE_CBC, iv)
    nr=unhexlify(str(StrongRandom().randint(1000000000000000,9999999999999999)))        
    D1=des.decrypt(nr)      
    #c
    longlongint1=struct.unpack('>Q',struct.pack('8s', D1))[0]
    longlongint2=struct.unpack('>Q',struct.pack('8s', nt2))[0]
    buff=struct.unpack('8s',struct.pack('>Q', longlongint1 ^ longlongint2))[0]     
    # d
    des = DES.new(key, DES.MODE_CBC, iv)
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
    des = DES.new(session_key, DES.MODE_CBC, iv)
    d = des.decrypt(data[0:8])
    res+=d
    i=8
    while not i == len(data):
        des = DES.new(session_key, DES.MODE_CBC, iv)  
        d = des.decrypt(xor(d, data[i:i+8])) 
        res+=d
        i+=8    
    return res

def decipher_CBC_receive_mode(session_key, data):
    iv = unhexlify("00"*8)
    des = DES.new(session_key, DES.MODE_CBC, iv)
    return des.decrypt(data)

def encipher_DES(mode, iv, key, data):
    des = DES.new(session_key, mode, iv)
    return des.encrypt(data)

def verify_s(cert_list, signature, data):
    digest=SHA.new(data).digest()    
    for x in cert_list:
        key = x.get_pubkey().get_rsa()
        subject = x.get_subject()
        key = pyRSA.importKey(key.as_pem())
        pub = key.publickey()
        l = hexstr_to_long(hexlify(signature))
        if pub.verify(digest, (l, '')):
            return subject
    return None
        



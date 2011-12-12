''' Utility functions for doing crypto stuff '''

#from pycryptopp import *
from Crypto.Cipher import DES, DES3
from crcISO import *
from M2Crypto import *

import Crypto.PublicKey.RSA as pyRSA
import Crypto.Hash.SHA as SHA
import base64
import struct

try:
    from Crypto.Random.random import StrongRandom
    from Crypto.Random.random import *
    def random_int_wrapper(nbytes):
        """returns a random integer in [0, 256**nbytes -1 ]"""
        return StrongRandom().randint(0,256**nbytes - 1)
except ImportError:
    import os
    def random_int_wrapper(nbytes):
        """returns a random integer in [0, 256**nbytes -1 ]
        Doesn't accept 0!
        """
        return reduce(lambda acc, x: acc* 256 + x,
            bytearray(os.urandom(nbytes)))

def gen_padded_random(nbytes):
    """returns a binary string of a random number padded to nbytes"""
    nr = hex(random_int_wrapper(nbytes))[2:] # remove 0x in front
    nr = nr[-1] == 'L' and nr[:-1] or nr # remove 'L' of long type if present
    nr = len(nr) < 2*nbytes and "0"* (2*nbytes-len(nr)) + nr or nr # padding
    return unhexlify(nr)

def long_to_hexstr(n):
    return hexlify(unhexlify("%x" % n)) 

def hexstr_to_long(s):
    return long(s, 16)

def perform_authentication(key, cipher_text):    
    iv = unhexlify("00"*8)
    #a
    algo = len(key) == 8 and DES or DES3
    des = algo.new(key, algo.MODE_CBC, iv) 
    nt = des.decrypt(cipher_text)       
    nt2 = nt[1:]+nt[:1]    
    # b        
    des = algo.new(key, algo.MODE_CBC, iv)
    nr = gen_padded_random(64/8)

    D1=des.decrypt(nr)      
    #c
    longlongint1=struct.unpack('>Q',struct.pack('8s', D1))[0]
    longlongint2=struct.unpack('>Q',struct.pack('8s', nt2))[0]
    buff=struct.unpack('8s',struct.pack('>Q', longlongint1 ^ longlongint2))[0]     
    # d
    des = algo.new(key, algo.MODE_CBC, iv)
    D2=des.decrypt(buff)    
    #e		
    return nt, nt2, nr, D1, D2  

def xor(a,b):
    longlongint1=struct.unpack('>Q',struct.pack('8s', a))[0]
    longlongint2=struct.unpack('>Q',struct.pack('8s', b))[0]
    buff=struct.unpack('8s',struct.pack('>Q', longlongint1 ^ longlongint2))[0]  
    return buff

def decipher_CBC_send_mode(session_key, data, algo=DES):
    """default algo DES"""
    algo = len(session_key) == 8 and DES or DES3
    res = ""
    iv = unhexlify("00"*8)
    des = algo.new(session_key, algo.MODE_CBC, iv)
    d = des.decrypt(data[0:8])
    res+=d
    i=8
    while not i == len(data):
        des = algo.new(session_key, algo.MODE_CBC, iv)  
        d = des.decrypt(xor(d, data[i:i+8])) 
        res+=d
        i+=8    
    return res

def decipher_CBC_receive_mode(session_key, data):
    iv = unhexlify("00"*8)
    algo = len(session_key) == 8 and DES or DES3
    des = algo.new(session_key, algo.MODE_CBC, iv)
    return des.decrypt(data)

def encipher_DES_CBC(iv, key, data):
    algo = len(key) == 8 and DES or DES3
    des = algo.new(session_key, algo.MODE_CBC, iv)
    return des.encrypt(data)

def verify_s(cert_list, signature, data):
    """returns the subject of the first certificate in <cert_list> that makes the
    <signature> match the SHA hash of the data.
    If no certificate does it, return None"""
    """digest=SHA.new(data).digest()    
    for x in cert_list:
        key = x.get_pubkey().get_rsa()
        subject = x.get_subject()
        key = pyRSA.importKey(key.as_pem())
        pub = key.publickey()
        l = hexstr_to_long(hexlify(signature))
        if pub.verify(digest, (l, '')):
            return subject
    return None"""
    return 12
        



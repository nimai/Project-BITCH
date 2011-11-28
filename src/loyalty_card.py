''' Representation of an RFID loyalty card 
     along with methods to interact with the physical RFID card '''

from smartcard.System import readers
from smartcard.CardType import ATRCardType, AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.Exceptions import *
from smartcard.util import toHexString, toBytes
from binascii import hexlify, unhexlify 
from Crypto.Cipher import DES
import Crypto.Random.random
from Crypto.Random.random import *

from command_builder import * 
from crypto import * 
import struct


def perform_command(conn, apdu):
    response, sw1, sw2 = conn.transmit(apdu)        
    get_resp = get_response_apdu(sw2)    
    response, sw1, sw2 = conn.transmit(get_resp)    
    print 'response: ', toHexString(response), ' status words: ', "%x %x" % (sw1, sw2)
    return response, sw1, sw2

def bytes_to_hexstr(array):
    return toHexString(array).replace(" ","").lower()  

def hexstr_to_bytes(string):
    return map(ord, string.decode("hex"))

def str_to_bytes(string):
    return map(ord, string.decode("ascii"))

def bytes_to_str(array):
    res = ""
    for x in array:
        res += chr(x)
    return res
    

def int_to_bytes(integer):
    res = []
    binary_string = bin(integer)
    binary_string = binary_string[2:len(binary_string)]    
    padding = 0
    if not len(binary_string) % 8 == 0:
        padding =  8 - len(binary_string) % 8
    binary_string = ("0"*padding)+binary_string    
    i = 0
    while not i == (len(binary_string)):    
        tmp = binary_string[i:i+8]            
        res.append(int(tmp, 2))
        i+=8		
    return res
    
def int_to_bytes_with_padding(integer, n):
    res = int_to_bytes(integer)
    for i in range(0, n-len(res)):
        res.append(0)
    return res   

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

class TagException(Exception):    
    def __init__(self, msg):        
        self.msg = msg
        

class LoyaltyCard:
    
    def __init__(self, p_k_enc, p_k_shop, p_ca, conn):
        self.__P_K_enc = p_k_enc
        self.__P_K_shop = p_k_shop
        self.__P_ca = p_ca 
        self.__connection = conn  
        self.__kdesfire = unhexlify("00"*8)            
                

    def __select_application(self, aid):
        apdu = select_application_apdu(aid)
        print "select application"
        response, sw1, sw2 = perform_command(self.__connection, apdu)
        if not(response[len(response)-2] == 0x91 and response[len(response)-1] == 0x00 and sw1 == 0x90 and sw2 == 0x00):            
            raise TagException('Application selection has failed!')

    def __create_application(self, aid, key_settings, num_of_keys):
        apdu = create_application_apdu(aid, key_settings, num_of_keys)
        print "create application: ", toHexString(apdu) 
        response, sw1, sw2 = perform_command(self.__connection, apdu)
        if not(response[len(response)-2] == 0x91 and response[len(response)-1] == 0x00 and sw1 == 0x90 and sw2 == 0x00):            
            raise TagException('Application creation has failed!')
    
    def __delete_application(self, aid):
        apdu = delete_application_apdu(aid)
        print "delete application"
        response, sw1, sw2 = perform_command(self.__connection, apdu)
        if not(response[len(response)-2] == 0x91 and response[len(response)-1] == 0x00 and sw1 == 0x90 and sw2 == 0x00):            
            raise TagException('Application deletion has failed!')        

    def __create_file(self, file_no, com_set, acc_rights, file_size):
        fs = int_to_bytes_with_padding(file_size, 3)                     
        apdu = create_file_apdu(file_no, com_set, acc_rights, fs)
        print "create file"
        response, sw1, sw2 = perform_command(self.__connection, apdu)
        if not(response[len(response)-2] == 0x91 and response[len(response)-1] == 0x00 and sw1 == 0x90 and sw2 == 0x00):            
            raise TagException('File creation has failed!')

    def __erase_memory(self):
        apdu = format_PICC_apdu()
        print "erase memory"
        response, sw1, sw2 = perform_command(self.__connection, apdu)
        if not(response[len(response)-2] == 0x91 and response[len(response)-1] == 0x00 and sw1 == 0x90 and sw2 == 0x00):            
            raise TagException('PICC formating has failed')

    def __change_key(self, aid, key_no, new_key):
        pass

    def __authenticate(self, key_no, key):
        apdu = authentication_1st_step_apdu(key_no)
        print "authentication 1st step"
        response, sw1, sw2 = perform_command(self.__connection, apdu)
        if not(response[len(response)-2] == 0x91 and response[len(response)-1] == 0xAF and sw1 == 0x90 and sw2 == 0x00):            
            raise TagException('Authentication has failed (1st step)!')
        
        cyper_text = unhexlify(bytes_to_hexstr(response[3:11]))        
        nt, nt2, nr, D1, D2 = perform_authentication(key, cyper_text) 
        deciphered_data = hexlify(D1)+hexlify(D2) 	
        apdu = authentication_2nd_step_apdu(hexstr_to_bytes(deciphered_data))
        print "authentication 2nd step"
        response, sw1, sw2 = perform_command(self.__connection, apdu)
        if not(response[len(response)-2] == 0x91 and response[len(response)-1] == 0x00 and sw1 == 0x90 and sw2 == 0x00):            
            raise TagException('Authentication has failed (2nd step)!')

        des = DES.new(key, DES.MODE_CBC, unhexlify("00"*8)) 
        nr2 = des.decrypt(unhexlify(bytes_to_hexstr(response[3:11])))
        if not nr2 == nr[1:]+nr[:1]:
            raise TagException('Authentication has failed (2nd step)!')
        
        if hexlify(key[0:4]) == hexlify(key[4:8]):
            return hexlify(nr[0:4]) + hexlify(nt[0:4])

        return hexlify(nr[0:4]) + hexlify(nt[0:4]) + hexlify(nr[4:8]) + hexlify(nt[4:8])
        

    def __write_data(self, file_no, offset, data, key):
        padding = 0
        bdata = str_to_bytes(data)     
        data_len = len(bdata)
        crc = crc16_iso14443a(data)#[::-1]   
        bdata.extend(crc)
        if not len(bdata) % 8 == 0:
            padding = 8 - (len(bdata) % 8)
        for i in range(0, padding):
            bdata.append(0x00)
        print "p: ", bytes_to_hexstr(bdata)
        print "c: ", hexlify(decipher_CBC_send_mode(key, bytes_to_str(bdata)))
        deciphered_data = hexstr_to_bytes(hexlify(decipher_CBC_send_mode(key, bytes_to_str(bdata)))) # wouaw :o 
     
        if len(deciphered_data) < 53:                           
            apdu = write_data_1st_step_apdu(file_no, int_to_bytes_with_padding(offset, 3), int_to_bytes_with_padding(data_len , 3), deciphered_data)
            print "write data: ", toHexString(apdu)
            response, sw1, sw2 = perform_command(self.__connection, apdu)
            if not(response[len(response)-2] == 0x91 and response[len(response)-1] == 0x00 and sw1 == 0x90 and sw2 == 0x00):            
                raise TagException('Write data has failed!')

        else:
            apdu = write_data_1st_step_apdu(file_no, int_to_bytes_with_padding(offset, 3) , int_to_bytes_with_padding(data_len, 3), deciphered_data[0:52])
            print "write data"
            response, sw1, sw2 = perform_command(self.__connection, apdu)
            if not(response[len(response)-2] == 0x91 and response[len(response)-1] == 0x00 and sw1 == 0x90 and sw2 == 0x00):            
                raise TagException('Write data has failed!') 
            i = 52
            while not i == len(deciphered_data):
                if (i+59) > len(deciphered_data):
                    end = len(deciphered_data)
                else:
                    end = i+59
                apdu = write_data_2nd_step_apdu(deciphered_data[i:end])
                print "write data"
                response, sw1, sw2 = perform_command(self.__connection, apdu)
                if not(response[len(response)-2] == 0x91 and response[len(response)-1] == 0x00 and sw1 == 0x90 and sw2 == 0x00):            
                    raise TagException('Write data has failed!')
            
        
        
    def __read_data(self, file_no, key, encrypted):
        return None

    def __verify_signature(self):
        pass

    def poll(self):
        apdu = polling_apdu(1)
        perform_command(self.__connection, apdu)        
        # the following code doesn't work with the card since the ATR is
        # wrong!!
        #cardtype = ATRCardType(toBytes( "3B 04 41 11 77 81" ))        
        #cardrequest = CardRequest( timeout=5, cardType=cardtype )
        #try:
        #    self.__cardservice = cardrequest.waitforcard()
        #except CardRequestTimeoutException:
        #    raise
        #self.__cardservice.connection.connect()
        #print toHexString( self.__cardservice.connection.getATR() )
        	

    def initialize(self):
        #/!\ does not work because DES seems to be dependent from an encryption to the other
        #random_gen = StrongRandom() 
        #self.__kdesfire = DES.new(str(random_gen.randint(10000000,99999999)), DES.MODE_CBC)
        #self.__k = DES.new(str(random_gen.randint(10000000,99999999)), DES.MODE_CBC)
        #self.__km1 = DES.new(str(random_gen.randint(10000000,99999999)), DES.MODE_CBC)
        #self.__km2 = DES.new(str(random_gen.randint(10000000,99999999)), DES.MODE_CBC)
        #self.__kw1 = DES.new(str(random_gen.randint(10000000,99999999)), DES.MODE_CBC)   
 
        #self.__kdesfire = DES.new(unhexlify("00"*8), DES.MODE_CBC, unhexlify("00"*8))
        #self.__k = DES.new(unhexlify("00"*8), DES.MODE_CBC, unhexlify("00"*8))
        #self.__km1 = DES.new(unhexlify("00"*8), DES.MODE_CBC, unhexlify("00"*8))
        #self.__km2 = DES.new(unhexlify("00"*8), DES.MODE_CBC, unhexlify("00"*8))
        #self.__kw1 = DES.new(unhexlify("00"*8), DES.MODE_CBC, unhexlify("00"*8))    
	
	self.__kdesfire = unhexlify("00"*8)
        self.__k = unhexlify("00"*8)
        self.__km1 = unhexlify("00"*8)
        self.__km2 = unhexlify("00"*8)
        self.__kw1 = unhexlify("00"*8)
        
        self.__select_application(0x00)
        self.__authenticate(0x00, self.__kdesfire)
        self.__create_application(0x01, 0x0B, 0x02) 
        self.__select_application(0x01)
        self.__authenticate(0x00, self.__km1)       
        self.__create_file(1, 3, [0x00, 0xE1], 128)
        sk = unhexlify(self.__authenticate(0x01, self.__kw1))

        self.__write_data(1, 0, "hello world", sk)
        

    def reset(self):
        self.__select_application(0)
        self.__authenticate(0, self.__kdesfire)
        #self.__delete_application(1)    
        self.__erase_memory()      

    def get_counter(self):
        sk = self.__authenticate(2,1,self.__k)
        c = self.__read_data(2, 1, sk)
        return "2 sandwiches purchased so far"

    def get_log(self):
        sk = self.__authenticate(2,1,self.__k)
        log = self.__read_data(2, 2, sk)
        return "22/10/2011 - 12:51 - Subway-like\n" + "02/11/2011 - 13:28 - Bob's shop"

    def add_sandwich(self, n):
        pass

    

''' Representation of an FID loyalty card 
     along with methods to interact with the physical RFID card '''

from smartcard.System import readers
from smartcard.CardType import ATRCardType, AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.Exceptions import *
from smartcard.util import toHexString, toBytes
from binascii import hexlify, unhexlify 
from datetime import datetime
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
    #print 'response: ', toHexString(response), ' status words: ', "%x %x" % (sw1, sw2)
    return response, sw1, sw2

def bytes_to_hexstr(array):
    return toHexString(array).replace(" ","").lower()  

def hexstr_to_bytes(string):
    return map(ord, string.decode("hex"))

def str_to_bytes(string):
    """converts an ascii string to a list of their ascii values"""
    return map(ord, string.decode("ascii"))

def bytes_to_str(array):
    res = ""
    for x in array:
        res += chr(x)
    return res

def add_left_padding(bytes, padding, n):
    for i in range(len(bytes), n):
        bytes = [padding]+bytes   
    return bytes
     


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
    return res[::-1]
    
def int_to_bytes_with_padding(integer, n):
    res = int_to_bytes(integer)
    for i in range(0, n-len(res)):
        res.append(0)
    return res   

def long_to_bytes(a):    
    return int_to_bytes(a)

def encode_counter(c):
    res = str_to_bytes(str(c))
    if len(res) < 4:
        for i in range(len(res), 4):
            res = [0x30]+res
    for i in range(len(res), 32):
        res.append(0) 
    return res

def decode_counter(raw_data):
    c_bytes = hexstr_to_bytes(hexlify(raw_data))[0:4]
    c_string = bytes_to_str(c_bytes)
    return int(c_string)

def encode_log(c, shop_name, p_k_shop):    
    res = []
    date = datetime.now()
    res.extend(str_to_bytes(str(date.year)[2:4]))    
    res.extend(add_left_padding(str_to_bytes(str(date.month)), 0x30 , 2))    
    res.extend(add_left_padding(str_to_bytes(str(date.day)), 0x30 , 2))    
    res.extend(add_left_padding(str_to_bytes(str(date.hour)), 0x30 , 2))    
    res.extend(add_left_padding(str_to_bytes(str(date.minute)), 0x30 , 2))  
  
    c_bytes = str_to_bytes(str(c))
    for i in range(len(c_bytes),4):
        c_bytes = [0x30]+c_bytes 
    res.extend(c_bytes)
    
    shop_name_bytes = str_to_bytes(shop_name)
    for i in range(len(shop_name_bytes), 58):
        shop_name_bytes.append(ord(" "))   
    res.extend(shop_name_bytes)
 
    log = bytes_to_hexstr(res)
    s = long_to_bytes(p_k_shop.sign(log ,32)[0])
    res.extend(s)   
    print bytes_to_str(res[0:72]) 
    return res

def decode_log(raw_data):
    log_bytes = hexstr_to_bytes(hexlify(raw_data))[0:72]
    return bytes_to_str(log_bytes)

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
        self.__k = unhexlify("00"*8)     
                

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
        data_len = len(data)
        crc = crc16_iso14443a(data) 
        data.extend(crc)
        if not len(data) % 8 == 0:
            padding = 8 - (len(data) % 8)
        for i in range(0, padding):
            data.append(0x00)        
        deciphered_data = hexstr_to_bytes(hexlify(decipher_CBC_send_mode(key, bytes_to_str(data)))) # wouaw :o 
        
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
            if not(response[len(response)-2] == 0x91 and (response[len(response)-1] == 0xAF or response[len(response)-1] == 0x00) 
            and sw1 == 0x90 and sw2 == 0x00):            
                raise TagException('Write data has failed!') 
            i = 52
            while i < len(deciphered_data):
                if (i+59) > len(deciphered_data):
                    end = len(deciphered_data)
                else:
                    end = i+59
                apdu = write_data_2nd_step_apdu(deciphered_data[i:end])
                print "write data 2nd step: ", toHexString(apdu)
                response, sw1, sw2 = perform_command(self.__connection, apdu)
                if not(response[len(response)-2] == 0x91 and (response[len(response)-1] == 0xAF or response[len(response)-1] == 0x00) 
                and sw1 == 0x90 and sw2 == 0x00):            
                    raise TagException('Write data has failed!') 
                i+=59
            
        
        
    def __read_data(self, file_no, offset, length, key):
        data = ""
        apdu = read_data_1st_step_apdu(file_no, int_to_bytes_with_padding(offset , 3), int_to_bytes_with_padding(length , 3))
        print "read data 1st step"
        response, sw1, sw2 = perform_command(self.__connection, apdu)
        if not (response[len(response)-2] == 0x91 and sw1 == 0x90 and sw2 == 0x00): 
            raise TagException('Read data has failed (1st step)!')	
	if not (response[len(response)-1] == 0x00 or response[len(response)-1] == 0xAF):
            raise TagException('Read data has failed (1st step)')
        data += bytes_to_str(response[3:len(response)-2])
        if response[len(response)-1] == 0xAF:
            while True:
                apdu = read_data_2nd_step_apdu()
                print "read data 2nd step"
                response, sw1, sw2 = perform_command(self.__connection, apdu)
                if not (response[len(response)-2] == 0x91 and sw1 == 0x90 and sw2 == 0x00): 
                    raise TagException('Read data has failed (2nd step)!')	
	        if not (response[len(response)-1] == 0x00 or response[len(response)-1] == 0xAF):
                    raise TagException('Read data has failed (2nd step)')
                data += bytes_to_str(response[3:len(response)-2])
                if response[len(response)-1] == 0x00:
                    break
        if key == None:
            return data
        return decipher_CBC_receive_mode(key, data)

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
        self.__create_file(2, 3, [0x00, 0xE1], 128)

        sk = unhexlify(self.__authenticate(0x01, self.__kw1))        
        E = hexlify(self.__P_K_enc.encrypt(self.__k, 32)[0])
        self.__write_data(1, 0, hexstr_to_bytes(E), sk)
 
        S = self.__P_K_shop.sign(E ,32)[0]
        self.__write_data(2, 0, long_to_bytes(S), sk)
        """read = self.__read_data(2, 0, 128, None)
        print "read: ", read"""

        self.__select_application(0x00)
        self.__authenticate(0x00, self.__kdesfire)
        self.__create_application(0x02, 0x0B, 0x02) 
        self.__select_application(0x02)
        sk = unhexlify(self.__authenticate(0x00, self.__km2))
        self.__create_file(1, 3, [0x10, 0xE1], 32)
        self.__create_file(2, 3, [0x10, 0x11], 2000)
        
        sk = unhexlify(self.__authenticate(0x01, self.__k)) 
        self.__write_data(1, 0, encode_counter(0), sk)  
        self.__write_data(2, 0, str_to_bytes("."*2000), sk) 



    def reset(self):
        self.__select_application(0)
        self.__authenticate(0, self.__kdesfire)
        self.__erase_memory()      

    def get_counter(self):
        self.__select_application(0x02)
        c = decode_counter(self.__read_data(1, 0, 32, None))
        return str(c)+" sandwiches purchased so far"

    def get_log(self):
        log = ""
        self.__select_application(0x02)
        sk = unhexlify(self.__authenticate(0x01, self.__k)) 
        for i in range(0,10):
            log += decode_log(self.__read_data(2, 200*i, 78, sk))
            log += "\n"
            #i+=1
        return log

    def add_sandwich(self, n):
        self.__select_application(0x02)
        #read = hexstr_to_bytes(hexlify(self.__read_data(1, 0, 32, None)))
        #print "read: ", read[0:4]
        old_c = decode_counter(self.__read_data(1, 0, 32, None))
        new_c = old_c + 1
        if new_c % 10 == 0:
            print "This sandwich is free!"
        sk = unhexlify(self.__authenticate(0x01, self.__k)) 
        self.__write_data(1, 0, encode_counter(new_c), sk) 
        log = encode_log(new_c,"Attrapez-les-tous", self.__P_K_shop)
        self.__write_data(2, (old_c % 10) * 200, log, sk) 
        
        
        
    

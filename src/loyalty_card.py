''' Representation of an FID loyalty card 
     along with methods to interact with the physical RFID card '''

from smartcard.System import readers
from smartcard.CardType import ATRCardType, AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.Exceptions import *
from smartcard.util import toHexString, toBytes
from binascii import hexlify, unhexlify 
from datetime import datetime
from Crypto.Cipher import DES, DES3
import Crypto.Hash.SHA as SHA
from M2Crypto import RSA
import hashlib
from crypto import * 
import struct
from keystore import Keystore

from bitch_exceptions import *
from command_builder import * 
from desfire_commands_meanings import desfire_cmd_meaning
from sw2_error_codes import sw2_error_codes

DEBUG=False # global debug flag

def analyse_return(response, sw1, sw2):
    print 'response: ', toHexString(response), ' status words: ', "%x %x" % (sw1, sw2)
    if sw1 == 0x90 and sw2 == 0 and response[-1] != 0:
        try:
            print "Desfire: " + hex(response[-1]) + " " + sw2_error_codes[response[-1]]
        except KeyError: # not in table
            pass 


def perform_command(conn, apdu):
    """transmit the give apdu. returns either the response, or the data if
    additional data is available"""
    if DEBUG: print '> ' + \
        (len(apdu) >= 10 and apdu[9] in desfire_cmd_meaning and \
            desfire_cmd_meaning[apdu[9]] or '') + toHexString(apdu) 
    response, sw1, sw2 = conn.transmit(apdu)        
    if sw1 == 0x61 and sw2 > 0:
        get_resp = get_response_apdu(sw2)    
        response, sw1, sw2 = conn.transmit(get_resp)    
        if DEBUG: 
            analyse_return(response, sw1, sw2)
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
    """returns a list of integers [0, 255] representing the bytes of <integer>
    in MSB order (that is lst[0] = less significant byte)"""
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
        i += 8
    return res[::-1]
    
def int_to_bytes_with_padding(integer, n):
    res = int_to_bytes(integer)
    for i in range(0, n-len(res)):
        res.append(0)
    return res   

def long_to_bytes(a):    
    return int_to_bytes(a)

def long_to_hexstr(n):
    return hexlify(unhexlify("%x" % n)) 

def hexstr_to_long(s):
    return long(s, 16)

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
        shop_name_bytes.append(0x00)
        #shop_name_bytes.append(ord(" "))   
    res.extend(shop_name_bytes)
 
    log = bytes_to_hexstr(res)
    s = hexstr_to_bytes(hexlify(p_k_shop.sign(unhexlify(log))))   
    #s = long_to_bytes(p_k_shop.sign(log ,32)[0])
    res.extend(s)       
    return res

def decode_log(raw_data):
    log_bytes = hexstr_to_bytes(hexlify(raw_data))[0:72]
    return bytes_to_str(log_bytes)

class TagException(Exception):    
    def __init__(self, msg):        
        self.msg = msg
        

class LoyaltyCard:
    
    def __init__(self, p_k_enc, p_k_shop, p_ca, cert, conn):
        self.__P_K_enc = p_k_enc
        self.__P_K_shop = p_k_shop
        self.__P_ca = p_ca 
        self.__connection = conn  
        self.uid = bytes_to_hexstr(self.poll())
        store = Keystore()
        self.__kdesfire = unhexlify(store.getMasterKey(self.uid) or "00"*8)
        if len(self.__kdesfire) not in [8, 16]:
            raise WrongKey("kdesfire from keystore doesn't have a good size " \
                + "(" + len(self.__kdesfire) + ")")
        self.__cert = cert

    def select_application(self, aid):
        apdu = select_application_apdu(aid)
        #print "select application"
        response, sw1, sw2 = perform_command(self.__connection, apdu)
        if not(response[len(response)-2] == 0x91 and response[len(response)-1] == 0x00 and sw1 == 0x90 and sw2 == 0x00):            
            raise TagException('Application selection has failed!')

    def __create_application(self, aid, key_settings, num_of_keys):
        apdu = create_application_apdu(aid, key_settings, num_of_keys)
        #print "create application: ", toHexString(apdu) 
        response, sw1, sw2 = perform_command(self.__connection, apdu)
        if not(response[len(response)-2] == 0x91 and response[len(response)-1] == 0x00 and sw1 == 0x90 and sw2 == 0x00):            
            raise TagException('Application creation has failed!')
    
    def __delete_application(self, aid):
        apdu = delete_application_apdu(aid)
        #print "delete application"
        response, sw1, sw2 = perform_command(self.__connection, apdu)
        if not(response[len(response)-2] == 0x91 and response[len(response)-1] == 0x00 and sw1 == 0x90 and sw2 == 0x00):            
            raise TagException('Application deletion has failed!')        

    def __create_file(self, file_no, com_set, acc_rights, file_size):
        fs = int_to_bytes_with_padding(file_size, 3)                           
        apdu = create_file_apdu(file_no, com_set, acc_rights, fs)
        #print "create file"
        response, sw1, sw2 = perform_command(self.__connection, apdu)
        if not(response[len(response)-2] == 0x91 and response[len(response)-1] == 0x00 and sw1 == 0x90 and sw2 == 0x00):            
            raise TagException('File creation has failed!')

    def __erase_memory(self):
        apdu = format_PICC_apdu()
        #print "erase memory"
        response, sw1, sw2 = perform_command(self.__connection, apdu)
        if not(response[len(response)-2] == 0x91 and response[len(response)-1] == 0x00 and sw1 == 0x90 and sw2 == 0x00):            
            raise TagException('PICC formating has failed')

    def change_key(self, aid, key_no, key_auth, old_key, new_key):
        """wrapper for the different ways of changing key
        @pre: the key_auth is equal to the old_key if the key_no is 0
        @post: if the master key is changed, it is backed-up externally
        @return: on success, the new session key is returned"""
        # master key
        if key_no == 0 and aid == 0:
            ret = self.change_key1(aid, key_no, old_key, new_key)
            Keystore().setMasterKey(self.uid, hexlify(new_key))
            if DEBUG:
                print "Changed master key, new one is %s" \
                    % Keystore().getMasterKey(self.uid)
            return ret
        elif key_no == 0:
            return self.change_key1(aid, key_no, old_key, new_key)
        else:
            return self.change_key2(aid, key_no, key_auth, old_key, new_key)


    def change_key1(self, aid, key_no, old_key, new_key):
        """changes the old key key_no of application aid.
        we assume that the CHANGE_KEY key is not set to 0xE.
        @pre: one card was polled and is still on the reader
            - aid, key_no,  
               are either integers
               key_no must be 0
            - old_key, new_key
               are binary strings
        @post: new_key is now in use and the application aid is now authentified
            with that new_key
        @return: the new session key from the autentication is returned
        """
        self.select_application(aid)
        current_session_k = unhexlify(self.__authenticate(key_no, old_key))
        with open('change_key.log', 'ab') as log: # DEBUG
            log.write("aid:" + str(aid) + " keyno:" + str(key_no) + " newkey:" + hexlify(new_key))

        try:
            self.__change_key_core(key_no, current_session_k, old_key, new_key)
            with open('change_key.log', 'ab') as log: # DEBUG
                log.write(" now in use\n")
        except TagException:
            with open('change_key.log', 'ab') as log: # DEBUG
                log.write(" failed to change\n")
            raise
        except BaseException:
            with open('change_key.log', 'ab') as log:
                log.write(" Failed: unexpected error\n")
            raise
            
        new_session_k = self.__authenticate(key_no, new_key)
        return new_session_k

    def change_key2(self, aid, key_no, key_auth, old_key, new_key):
        """second method to change a key:
        @pre 
        """
        self.select_application(aid)
        current_session_k = unhexlify(self.__authenticate(0, key_auth))
        with open('change_key.log', 'ab') as log: # DEBUG
            log.write("aid:" + str(aid) + " keyno:" + str(key_no) + " newkey:" + hexlify(new_key))

        try:
            self.__change_key_core(key_no, current_session_k, old_key, new_key)
            with open('change_key.log', 'ab') as log: # DEBUG
                log.write(" now in use\n")
        except TagException:
            with open('change_key.log', 'ab') as log: # DEBUG
                log.write(" failed to change\n")
            raise
        except BaseException:
            with open('change_key.log', 'ab') as log:
                log.write(" Failed: unexpected error\n")
            raise
            
        return current_session_k

    def __change_key_core(self, key_no, current_session_k, current_k, new_key):
        """replaces the current key key_no by the new_key
        @pre: must have authenticated an application and the current_session_k
        must still be valid.
            - key_no  must be 1
            - current_session_k, new_key must be binary strings of 16 bytes long
            - we assume that the CHANGE_KEY key is not set to 0xE and that if
              key_no is different from 0, the data frame must be generated the
              way that xores the two keys
        @post: DEBUG: a log file change_key.log is appended with the new key and
            the result of the manipulation"""
        if DEBUG: print current_session_k, "length", len(current_session_k)
        if len(current_session_k) not in [8, 16] or len(current_k) not in [8, 16] \
                or len(new_key) != 16:
            raise ValueError(("either current_session_k (len:{}), current (old)"\
                + " key (len:{}), or new key (len:{}) is not 16 bytes")\
                .format(len(current_session_k), len(current_k), len(new_key)))
        new_key_bytes = hexstr_to_bytes(hexlify(new_key))
        if len(current_k) == 8:
            current_k = current_k + current_k
        xor_keys = map(lambda x, y: x ^ y, 
            hexstr_to_bytes(hexlify(current_k)), new_key_bytes)
        crc = crc16_iso14443a(new_key_bytes)
        crc_xor = crc16_iso14443a(xor_keys)
        if key_no == 0: # normal
            data = unhexlify(bytes_to_hexstr(new_key_bytes + crc + [0, 0, 0, 0, 0, 0]))
        else:
            data = unhexlify(bytes_to_hexstr(xor_keys + crc_xor + crc + [0, 0, 0, 0]))
        deciphered_key_data = decipher_CBC_send_mode(current_session_k, data,
            len(current_session_k) == 8 and DES or DES3)
        response, sw1, sw2 = perform_command(self.__connection,
            change_key_command(key_no, deciphered_key_data))
        if not is_response_ok(response, sw1, sw2):
            raise TagException("Change key has failed!")

        
    def authenticate_manual(self, key_no, key):
        return self.__authenticate(key_no, key)

    def __authenticate(self, key_no, key):
        apdu = authentication_1st_step_apdu(key_no)
        #print "authentication 1st step"
        response, sw1, sw2 = perform_command(self.__connection, apdu)
        if not(response[len(response)-2] == 0x91 and response[len(response)-1] == 0xAF and sw1 == 0x90 and sw2 == 0x00):            
            raise TagException('Authentication has failed (1st step)!')
        
        cyper_text = unhexlify(bytes_to_hexstr(response[3:11]))        
        nt, nt2, nr, D1, D2 = perform_authentication(key, cyper_text) 
        deciphered_data = hexlify(D1)+hexlify(D2)       
        apdu = authentication_2nd_step_apdu(hexstr_to_bytes(deciphered_data))
        #print "authentication 2nd step"
        response, sw1, sw2 = perform_command(self.__connection, apdu)
        if not(response[len(response)-2] == 0x91 and response[len(response)-1] == 0x00 and sw1 == 0x90 and sw2 == 0x00):            
            raise TagException('Authentication has failed (2nd step)!')

        algo = len(key) == 8 and DES or DES3
        des = algo.new(key, algo.MODE_CBC, unhexlify("00"*8)) 
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
            #print "write data: ", toHexString(apdu)
            response, sw1, sw2 = perform_command(self.__connection, apdu)
            if not(response[len(response)-2] == 0x91 and response[len(response)-1] == 0x00 and sw1 == 0x90 and sw2 == 0x00):            
                raise TagException('Write data has failed!')

        else:
            apdu = write_data_1st_step_apdu(file_no, int_to_bytes_with_padding(offset, 3) , int_to_bytes_with_padding(data_len, 3), deciphered_data[0:52])
            #print "write data"
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
                #print "write data 2nd step: ", toHexString(apdu)
                response, sw1, sw2 = perform_command(self.__connection, apdu)
                if not(response[len(response)-2] == 0x91 and (response[len(response)-1] == 0xAF or response[len(response)-1] == 0x00) 
                and sw1 == 0x90 and sw2 == 0x00):            
                    raise TagException('Write data has failed!') 
                i+=59
            
        
        
    def read_data(self, file_no, offset, length, key):
        data = ""
        apdu = read_data_1st_step_apdu(file_no, int_to_bytes_with_padding(offset , 3), int_to_bytes_with_padding(length , 3))
        #print "read data 1st step"
        response, sw1, sw2 = perform_command(self.__connection, apdu)
        if not (response[len(response)-2] == 0x91 and sw1 == 0x90 and sw2 == 0x00): 
            raise TagException('Read data has failed (1st step)!')      
        if not (response[len(response)-1] == 0x00 or response[len(response)-1] == 0xAF):
            raise TagException('Read data has failed (1st step)')
        data += bytes_to_str(response[3:len(response)-2])
        if response[len(response)-1] == 0xAF:
            while True:
                apdu = read_data_2nd_step_apdu()
                #print "read data 2nd step"
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

    def poll(self):
        """returns the uid of the only present tag.
        raises MultipleTagsOnReader exception if multiple tags are present"""
        apdu = polling_apdu(1)
        response, sw1, sw2 = perform_command(self.__connection, apdu)       
        if len(response) < 3:
            raise TagException("No additional data was read")
        if not (sw1 == 0x90 and sw2 == 0x00):
            raise ResponseError("Error on poll: response " + str(response) \
                + " sw1: " + str(sw1) + " sw2: " + str(sw2))
        if response[2] != 1: # number of tags not one
            raise MultipleTagsOnReader("There is too much tags on the reader."
                + " Poll response: " + str(response) \
                + " sw1: " + str(sw1) + " sw2: " + str(sw2))
        uid = response[8:8 + response[7]]
        return uid
                

    def initialize(self):
        self.__kdesfire = unhexlify(Keystore().getMasterKey(self.uid) or "00"*8)
        __km1 = gen_padded_random(16)
        __km2 = gen_padded_random(16)
        __kw1 = gen_padded_random(16)
        def_key = unhexlify("00"*8) # default key
        __k = gen_padded_random(16)

        self.select_application(0x00)
        self.__authenticate(0x00, self.__kdesfire)
        if Keystore().getMasterKey(self.uid) is None:
            new_k = gen_padded_random(16)
            self.change_key(0, 0, self.__kdesfire, self.__kdesfire, new_k)
            self.__kdesfire = new_k
            
        self.__create_application(0x01, 0x0B, 0x02) 
        self.select_application(0x01)
        self.__authenticate(0x00, def_key) # default km1 value at init

        # master key 
        #stupid_k = unhexlify("11"*16)
        #self.change_key(0, 0, self.__kdesfire, self.__kdesfire, stupid_k)
        #self.change_key(0, 0, stupid_k, stupid_k, len(self.__kdesfire) == 8 and 
        #    self.__kdesfire + self.__kdesfire or self.__kdesfire)
        # km1
        self.change_key(1, 0, def_key, def_key, __km1)           
        # create files of aid 0x1
        self.__create_file(1, 3, [0xFF, 0xE1], 128)
        self.__create_file(2, 3, [0xFF, 0xE1], 128)
        #  
        self.change_key(1, 1, __km1, def_key, __kw1)      
        sk = unhexlify(self.__authenticate(0x01, __kw1))        
        #E = self.__P_K_enc.encrypt(self.__k, '')[0]
        E = self.__P_K_enc[0].public_encrypt(__k, RSA.pkcs1_padding)
        self.__write_data(1, 0, hexstr_to_bytes(hexlify(E)), sk)
        
        S = self.__P_K_shop.sign(hashlib.sha1(E).digest())              
        if DEBUG:
            print "sign(enc(K)) is set to ",str(S)
        self.__write_data(2, 0, hexstr_to_bytes(hexlify(S)), sk)        

        # APPLICATION 0
        self.select_application(0x00)
        self.__authenticate(0x00, self.__kdesfire)
        self.__create_application(0x02, 0x0B, 0x02) 
        # APPLICATION 2
        self.select_application(0x02)
        self.change_key(2, 0, def_key, def_key, __km2)  
        self.__create_file(1, 3, [0xFF, 0xE1], 32)
        self.__create_file(2, 3, [0x1F, 0x11], 2000)
        
        # change k
        self.change_key(2, 1, __km2, def_key, __k) 
        sk = unhexlify(self.__authenticate(0x01, __k)) 
        self.__write_data(1, 0, encode_counter(0), sk)  
        self.__write_data(2, 0, str_to_bytes("\0"*2000), sk)

    def authenticate(self):
        self.select_application(0x01)
        E = self.read_data(1, 0, 128, None)
        if hexlify(E)[0:1] == '0':
            E = unhexlify("00")       
        S = self.read_data(2, 0, 128, None)         
        subject = verify_s(self.__cert, S, E)
        if subject is None:
            if DEBUG:
                print 'THIS TAG COULD NOT BE AUTHENTICATED!'
            else:
                raise TagException('This tag could not be authenticated!')
        else:
            print "Tag authenticated (owner: "+str(subject)+")"

    def reset(self):
        self.select_application(0)
        self.__authenticate(0, self.__kdesfire)
        self.__erase_memory()      

    def get_counter(self):
        self.select_application(0x02)
        c = decode_counter(self.read_data(1, 0, 32, None))
        if c > 1:
            return str(c)+" sandwiches purchased so far"
        return str(c)+" sandwich purchased so far"

    def get_log(self):
        log = ""
        self.select_application(1)
        E = self.read_data(1, 0, 128, None)
        K = self.__P_K_enc[1].private_decrypt(E, RSA.pkcs1_padding)
        if (hexlify(K) == "00"):
            K = unhexlify("00"*8)

        self.select_application(0x02)
        sk = unhexlify(self.__authenticate(0x01, K)) 
        for i in range(0,10):
            log += decode_log(self.read_data(2, 200*i, 78, sk))
            log += "\n"
        return log

    def add_sandwich(self, n):

        self.select_application(0x02)
        old_c = decode_counter(self.read_data(1, 0, 32, None))
        new_c = old_c + 1

        self.select_application(0x01)
        E = self.read_data(1, 0, 128, None)
        if hexlify(E)[0:1] == '0':
            E = unhexlify("00")        
        K = self.__P_K_enc[1].private_decrypt(E, RSA.pkcs1_padding)
        if (hexlify(K) == "00"):
                K = unhexlify("00"*8)        
        S = self.read_data(2, 0, 128, None)         
        subject = verify_s(self.__cert, S, E)
        if subject is None:
            if DEBUG:
                print 'THIS TAG COULD NOT BE AUTHENTICATED!'
            else:
                raise TagException('This tag could not be authenticated!')
        else:
            print "Tag authenticated (owner: "+str(subject)+")"

        self.select_application(0x02)
        sk = unhexlify(self.__authenticate(0x01, K))
        self.__write_data(1, 0, encode_counter(new_c), sk) 
        log = encode_log(new_c,"Attrapez-les-tous", self.__P_K_shop)
        self.__write_data(2, (old_c % 10) * 200, log, sk) 
        if new_c % 10 == 0:
            print "This sandwich is free!"
        
        
    

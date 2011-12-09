''' Functions for building APDUs to send to the RFID card '''
from binascii import hexlify, unhexlify

def polling_apdu(max_tags):
    command = [0xFF, 0x00, 0x00, 0x00, 0x04, 0xD4, 0x4A, max_tags, 0x00]    
    return command

def get_response_apdu(nbytes):
    command = [0xFF, 0xC0, 0x00, 0x00, nbytes]
    return command

def insert_reader_transmit(command):
    return get_response_apdu(len(command)) + command

def select_application_apdu(aid):   
    """ /!\ works only for aid < 255 """
    command = [0xFF, 0x00, 0x00, 0x00, 0x0C, 0xD4, 0x40, 0x01, 0x90, 0x5A, 0x00, 0x00, 0x03, aid, 0x00, 0x00, 0x00]
    return command  

def create_application_apdu(aid, key_settings, num_of_keys):
    """ /!\ works only for aid < 255 """ 
    return [0xFF, 0x00, 0x00, 0x00, 0x0E, 0xD4, 0x40, 0x01, 0x90, 0xCA, 0x00, 0x00, 0x05, aid, 0x00, 0x00, key_settings, num_of_keys, 0x00]

def delete_application_apdu(aid):
    """ /!\ works only for aid < 255 """ 
    return [0xFF, 0x00, 0x00, 0x00, 0x0C, 0xD4, 0x40, 0x01, 0x90, 0xDA, 0x00, 0x00, 0x03, aid, 0x00, 0x00, 0x00]    

def authentication_1st_step_apdu(key_no):
    return [0xFF, 0x00, 0x00, 0x00, 0x0A, 0xD4, 0x40, 0x01, 0x90, 0x0A, 0x00, 0x00, 0x01, key_no, 0x00] 

def authentication_2nd_step_apdu(deciphered_data):
    res = [0xFF, 0x00, 0x00, 0x00, 0x19, 0xD4, 0x40, 0x01, 0x90, 0xAF, 0x00, 0x00, 0x10]
    res.extend(deciphered_data)
    res.append(0x00)
    return res 

def format_PICC_apdu():
    nbytes = 8
    return [0xFF, 0x00, 0x00, 0x00, nbytes, 0xD4, 0x40, 0x01, 0x90, 0xFC, 0x00, 0x00, 0x00]               


def create_file_apdu(file_no, com_set, acc_rights, file_size):
    res = [0xFF, 0x00, 0x00, 0x00, 0x10, 0xD4, 0x40, 0x01, 0x90, 0xCD, 0x00, 0x00, 0x07]
    res.append(file_no)
    res.append(com_set)
    res.extend(acc_rights)
    res.extend(file_size)
    res.append(0x00)
    return res

def write_data_1st_step_apdu(file_no, offset, length, deciphered_data):
    data_len = 7 + len(deciphered_data)
    nbytes = 9 + data_len        
    res = [0xFF, 0x00, 0x00, 0x00, nbytes, 0xD4, 0x40, 0x01, 0x90, 0x3D, 0x00, 0x00, data_len]
    res.append(file_no)
    res.extend(offset)
    res.extend(length)
    res.extend(deciphered_data)
    res.append(0x00)
    return res
  
         
def write_data_2nd_step_apdu(deciphered_data):
    data_len = len(deciphered_data)
    nbytes = 9 + data_len    
    res = [0xFF, 0x00, 0x00, 0x00, nbytes, 0xD4, 0x40, 0x01, 0x90, 0xAF, 0x00, 0x00, data_len]
    res.extend(deciphered_data)
    res.append(0x00)
    return res

def read_data_1st_step_apdu(file_no, offset, length):
    data_len = 7
    nbytes = 9 + data_len
    res = [0xFF, 0x00, 0x00, 0x00, nbytes, 0xD4, 0x40, 0x01, 0x90, 0xBD, 0x00, 0x00, data_len]
    res.append(file_no)
    res.extend(offset)
    res.extend(length)
    res.append(0x00)
    return res

def read_data_2nd_step_apdu():    
    nbytes = 8
    return [0xFF, 0x00, 0x00, 0x00, nbytes, 0xD4, 0x40, 0x01, 0x90, 0xAF, 0x00, 0x00, 0x00]    
  

def build_command(command_payload):
    """ builds a command, inserting the request for transfer [FF 00 00 00 XX]
    and the anticollision data before the command byte and it's parameters
    @pre: the command_payload can be a list of bytes or a binary data string
    @return the complete string of bytes"""
    try:
        command_payload.isalnum() # typical string call
        command = [ ord(x) for x in command_payload]
    except AttributeError:
        command = command_payload

    return [0xFF, 0x00, 0x00, 0x00, len(command) + 4, 0xD4, 0x40, 0x01, 0x90
        ] + command

def change_key_command(keyno, deciphered_key_data):
    """returns the command to send to change the key
    @pre: keyno must be an int, deciphered_key_data must be either a binary
    string or a list of bytes in integers.
    @return: the command to send"""
    try:
        deciphered_key_data.isalnum()
        dk_data = [ ord(x) for x in deciphered_key_data]
    except AttributeError:
        dk_data = deciphered_key_data
    if len(deciphered_key_data) != 24:
        print deciphered_key_data
        print hexlify(deciphered_key_data)
        print len(deciphered_key_data)
        raise ValueError("Deciphered key data must be 24 bytes long")

    return build_command([0xC4, 0, 0, 0x19, keyno] + dk_data + [ 0 ])

def is_response_ok(response, sw1, sw2):
    """check if the response is ok
    @return: true if the two last bytes of response are 0x91 and 0 and 
        sw1 is 0x90 and sw2 is 0.
        false otherwise."""
    return response[len(response)-2] == 0x91 and response[len(response)-1] == 0x00 and sw1 == 0x90 and sw2 == 0x00

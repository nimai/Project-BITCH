''' Functions for building APDUs to send to the RFID card '''

def polling_apdu(max_tags):
    command = [0xFF, 0x00, 0x00, 0x00, 0x04, 0xD4, 0x4A, max_tags, 0x00]
    return command

def get_response_apdu(nbytes):
    command = [0xFF, 0xC0, 0x00, 0x00, nbytes]
    return command

def insert_reader_transmit(command)
    return get_response_apdu(len(command)) + command

def select_application_apdu(aid):   
    command = [0xFF, 0x00, 0x00, 0x00, 0x0C, 0xD4, 0x40, 0x01, 0x90, hex(aid), 0x00, 0x00, 0x00]
    return command  

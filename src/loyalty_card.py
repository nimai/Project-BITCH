''' Representation of an RFID loyalty card 
     along with methods to interact with the physical RFID card '''

from smartcard.System import readers
from smartcard.CardType import ATRCardType, AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.Exceptions import *
from smartcard.util import toHexString, toBytes
from command_builder import * 
from crypto import *


def perform_command(conn, apdu):
    response, sw1, sw2 = conn.transmit(apdu)    
    get_resp = get_response_apdu(sw2)
    response, sw1, sw2 = conn.transmit(get_resp)
    print 'response: ', response, ' status words: ', "%x %x" % (sw1, sw2)
    return response, sw1, sw2          	


class LoyaltyCard:
    
    def __init__(self, conn):      
        self.__connection = conn             

    def __select_aid(self, aid):
        pass

    def __create_file(self, aid, no, access_rights):
        pass

    def __change_key(self, aid, key_no, new_key):
        pass

    def __authenticate(self, aid, key):
        pass

    def __write_data(self, aid, file_no, data):
        pass

    def __read_data(self, aid, file_no):
        pass

    def __verify_signature(self):
        pass

    def poll(self):
        apdu = polling_apdu()
        perform_command(self.__connection,apdu)        
        #/!\ following piece of code does not work with ACR122 reader, we need to do polling instead!
        #cardtype = ATRCardType(toBytes( "3B 04 41 11 77 81" ))        
        #cardrequest = CardRequest( timeout=5, cardType=cardtype )
        #try:
        #    self.__cardservice = cardrequest.waitforcard()
        #except CardRequestTimeoutException:
        #    raise
        #self.__cardservice.connection.connect()
        #print toHexString( self.__cardservice.connection.getATR() )
        	

    def initialize(self):
        select_application_apdu(5123)
        pass

    def reset(self):
        pass 

    def get_counter(self):
        return "2 sandwiches purchased so far"

    def get_log(self):
        return "22/10/2011 - 12:51 - Subway-like\n" + "02/11/2011 - 13:28 - Bob's shop"

    def add_sandwich(self, n):
        pass

    

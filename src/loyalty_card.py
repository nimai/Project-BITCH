''' Representation of an RFID loyalty card 
    along with methods to interact with the physical RFID card '''

from smartcard.System import readers
from smartcard.CardType import ATRCardType, AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.Exceptions import *
from smartcard.util import toHexString, toBytes
from crypto import *

class LoyaltyCard:
   
   __cardservice = None

   def __init__(self):
      pass   

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
      cardtype = ATRCardType(toBytes( "3B 04 41 11 77 81" ))
      #cardtype = AnyCardType()
      cardrequest = CardRequest( timeout=5, cardType=cardtype )
      try:
         self.__cardservice = cardrequest.waitforcard()
      except CardRequestTimeoutException:
         raise
      self.__cardservice.connection.connect()
      print toHexString( self.__cardservice.connection.getATR() )	

   def initialize(self):
      pass

   def reset(self):
      pass 

   def get_counter(self):
      return "2 sandwiches purchased so far"

   def get_log(self):
      return "22/10/2011 - 12:51 - Subway-like\n" + "02/11/2011 - 13:28 - Bob's shop"

   def add_sandwich(self, n):
      pass

   

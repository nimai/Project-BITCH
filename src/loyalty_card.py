''' Representation of an RFID loyalty card 
    along with methods to interact with the physical RFID card '''

from smartcard.System import readers
from crypto import *

class LoyaltyCard:
   
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
      pass

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

   

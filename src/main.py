import sys

from smartcard.Exceptions import CardRequestTimeoutException
from smartcard.System import readers
from smartcard.util import toHexString
from loyalty_card import *


def print_welcome():
   print "Welcome to sandwich-manager beta release."
   print "Type 'help' or 'h' for help."	

def print_help():  
   print "init   : initialize a new RFID loyalty card"
   print "reset  : reset an RFID loyalty card to factory settings"
   print "read   : read the content of an RFID loyalty card"
   print "buy    : add a purchase to an RFID loyalty card"
   print "quit   : try to guess" 

def init_loyalty_card():
   card = LoyaltyCard()
   try: 
      card.poll();       
   except CardRequestTimeoutException:
      print "No card detected!"
   else:
      card.initialize()
      print "Loyalty card successfully initialized"
   

def reset_loyalty_card():
   card = LoyaltyCard()
   try: 
      card.poll();       
   except CardRequestTimeoutException:
      print "No card detected!"
   else:   
      card.reset()
      print "Loyalty card successfully reset to factory settings"

def read_loyalty_card():
   card = LoyaltyCard()
   try: 
      card.poll();       
   except CardRequestTimeoutException:
      print "No card detected!"
   else:
      print card.get_counter()
      print card.get_log()

def buy_sandwich(n):
   card = LoyaltyCard()
   try: 
      card.poll();       
   except CardRequestTimeoutException:
      print "No card detected!"
   else:
      card.add_sandwich(n)
      print str(n)+" purchase(s) correctly added to the loyalty card"

def check_reader_availability():
   r=readers() 
   if len(r) < 1:
      print "Warning: no reader available"     
     

def main_loop():
   while 1:
      check_reader_availability()
      try:
         command = raw_input("$sandwich-manager> ") 	 
      except KeyboardInterrupt:
         break
      
      if command == "h" or command == "help":
         print_help()
      elif command == "init":
         init_loyalty_card()
      elif command == "reset":
         reset_loyalty_card()
      elif command == "read":
         read_loyalty_card()
      elif command == "buy":
         buy_sandwich(1)
      elif command == "quit":
         break	
      else:
         print "Unknown command"
      

def main(argv):
   print_welcome()
   main_loop()

if __name__ == "__main__":
    main(sys.argv[1:])

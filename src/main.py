#!/usr/bin/python
import sys

from smartcard.Exceptions import CardRequestTimeoutException, CardConnectionException
from smartcard.System import readers
from smartcard.util import toHexString
from threading import Timer
from M2Crypto import *
from binascii import hexlify, unhexlify 
from Crypto import PublicKey
import Crypto.PublicKey.RSA
from M2Crypto import RSA as RSA2
from loyalty_card import *
import readline # just adding this line improves raw_input() edition capabilities
import os

from bitch_exceptions import *

connection = None

""" Encryption/Decryption keys """
P_K_enc = None 
P_K_shop = None
P_ca = None

""" shops certificates """
cert = []

def print_welcome():
    print "Welcome to sandwich-manager beta release."
    r=readers() 
    if len(r) < 1:
        print "Warning: no reader available"         
    else:
        print "Reader: "+str(r[0])  
    print "Type 'help' or 'h' for help."	

def print_help():  
    print "init    : initialize a new RFID loyalty card"
    print "reset   : reset an RFID loyalty card to factory settings"
    print "read    : read the content of an RFID loyalty card"
    print "buy     : add a purchase to an RFID loyalty card"
    print "quit    : try to guess" 

def init_loyalty_card(p_k_enc, p_k_shop, p_ca, cert, conn): 
    t = Timer(3.0, reminder)
    t.start()
    try:
        card = LoyaltyCard(p_k_enc, p_k_shop, p_ca, cert, conn)
    except MultipleTagsOnReader:
        print "multiple tags present on reader"
        return
    finally:
        t.cancel()
    try:
        card.initialize()
    except TagException as instance:
        print instance.msg
    except CardConnectionException as instance:
	print instance.msg        
    else:
        print "Loyalty card successfully initialized"    

def reset_loyalty_card(p_k_enc, p_k_shop, p_ca, cert, conn): 
    try:
        input = raw_input("Are you sure you want to reset the tag to factory settings? ([y]/n)")
        if input not in ["y", "yes", ""]:
            return 	 
    except KeyboardInterrupt:
        return
    except EOFError:
        return 
    
    t = Timer(3.0, reminder)
    t.start()
    try:
        card = LoyaltyCard(p_k_enc, p_k_shop, p_ca, cert, conn)
    except MultipleTagsOnReader:
        print "multiple tags present on reader"
        return
    finally:
        t.cancel()
    try:
        card.reset()
    except TagException as instance:
        print instance.msg
    except CardConnectionException as instance:
	print instance.msg     
    else: 
        print "Loyalty card successfully reset to factory settings"

def read_loyalty_card(p_k_enc, p_k_shop, p_ca, cert, conn):
    t = Timer(3.0, reminder)
    t.start()
    try:
        card = LoyaltyCard(p_k_enc, p_k_shop, p_ca, cert, conn)
    except MultipleTagsOnReader:
        print "multiple tags present on reader"
        return
    finally:
        t.cancel()
    try:     
        card.authenticate()
        print card.get_counter()
        print card.get_log()
    except TagException as instance:
        print instance.msg
    except CardConnectionException as instance:
	print instance.msg    
        

def buy_sandwich(n, p_k_enc, p_k_shop, p_ca, cert, conn):
    t = Timer(3.0, reminder)
    t.start()
    try:
        card = LoyaltyCard(p_k_enc, p_k_shop, p_ca, cert, conn)
    except MultipleTagsOnReader:
        print "multiple tags present on reader"
        return
    finally:
        t.cancel()
    try:       	
        card.add_sandwich(n)
    except TagException as instance:
        print instance.msg
    except CardConnectionException as instance:
	print instance.msg
    else:
        print str(n)+" purchase(s) correctly added to the loyalty card"

def check_reader_availability():
    global connection
    r=readers() 
    if len(r) < 1:
        print "Warning: no reader available"    
    else:
        #from smartcard.CardConnectionObserver import ConsoleCardConnectionObserver
        #observer = ConsoleCardConnectionObserver()
        connection = r[0].createConnection()
        #connection.addObserver(observer)
        connection.connect()  
        
def reminder():
    print "No card detected! Please insert a card."  

def read_keys():
    global P_K_enc, P_K_shop, P_ca, K_K_enc     
    try:
        """key = open('./keys/P_enc--loyaltyEncryptionPublic.key').read()
        P_K_enc = PublicKey.RSA.importKey(key)    
        key = open('./keys/K_enc--loyaltyEncryptionPrivate.key').read()
        P_K_enc = PublicKey.RSA.importKey(key)  """

        pub = RSA2.load_pub_key("./keys/P_enc--loyaltyEncryptionPublic.key")
        priv = RSA2.load_key("./keys/K_enc--loyaltyEncryptionPrivate.key")
        P_K_enc = (pub, priv)


        key = open('./keys/P_CA--CAPublicKey.key').read()  
        P_ca = PublicKey.RSA.importKey(key)
        #key = open('./keys/Attrapez-les-tous_RSAprivate.key').read()  
        #P_K_shop = PublicKey.RSA.importKey(key)
        P_K_shop = RSA2.load_key("./keys/Attrapez-les-tous_RSAprivate.key")
    except IOError:
        print """
    Need the files:
    ./keys/P_enc--loyaltyEncryptionPublic.key
    ./keys/K_enc--loyaltyEncryptionPrivate.key
    ./keys/P_CA--CAPublicKey.key  
    ./keys/Attrapez-les-tous_RSAprivate.key  
    """
        exit(-1)

def read_certificates():
    global cert
    listing = os.listdir('./certificates')
    for infile in listing:        
        cert.append(X509.load_cert('./certificates/'+infile, X509.FORMAT_PEM))

    


def main_loop():
    while 1:
        check_reader_availability()
        try:
            command = raw_input("$sandwich-manager> ") 	 
        except KeyboardInterrupt:
            break
        except EOFError:
            break
        
        if command == "h" or command == "help":
            print_help()
        elif command == "init":
            init_loyalty_card(P_K_enc, P_K_shop, P_ca, cert, connection)
        elif command == "reset":
            reset_loyalty_card(P_K_enc, P_K_shop, P_ca, cert, connection)
        elif command == "read":
            read_loyalty_card(P_K_enc, P_K_shop, P_ca, cert, connection)
        elif command == "buy":
            buy_sandwich(1, P_K_enc, P_K_shop, P_ca, cert, connection)
        elif command == "":
            pass
        elif command == "quit":
            break	
        elif DEBUG:
            auth_cmd = "a" # "authenticate" shortcut
            select_cmd = "s" # "select_application"
            change_cmd = "c" # "change_key"

            if command[0:len(change_cmd)] == change_cmd:
                args = command.split()
                def help_change():
                    print "USAGE: change <AID> <KEYNO> <OLDKEY> <NEWKEY>"
                    print "  where <AID> and <KEYNO> are integers"
                    print "  and <OLDKEY> and <NEWKEY> are hexdecimal keys"
                    print "  whose size is resp. 8 or 16 bytes and 16 bytes"
                if len(args) != 5:
                    help_change()
                    continue

                try:
                    aid = int(args[1]) 
                        # TODO :remove aid: just the change_key command
                    keyno = int(args[2])
                    oldk = unhexlify(args[3])
                    newk = unhexlify(args[4])
                except ValueError:
                    print "either <AID> or <KEYNO> is no a base 10 int"
                    help_change()
                    continue
                except TypeError:
                    print "either <OLDKEY> or <NEWKEY> is not a proper hex string"
                    help_change()
                    continue
                
                if len(oldk) not in [8, 16]:
                    print "<OLDKEY> is not 8 or 16 bytes long"
                    help_change()
                    continue
                
                if len(newk) != 16:
                    print "<NEWKEY> is not 16 bytes long"
                    help_change()
                    continue

                LoyaltyCard(P_K_enc, P_K_shop, P_ca, cert, connection
                    ).change_key(aid, keyno, oldk, newk)

            elif command[0:len(auth_cmd)] == auth_cmd:
                args = command.split()
                def help_auth():
                    print "USAGE: auth <KEYNO> <KEY>"
                    print "  where <KEYNO> is integer"
                    print "  and <KEY> is a 8 or 16 bytes hex"
                if len(args) != 3:
                    help_auth()
                    continue

                try:
                    keyno = int(args[1])
                    k = unhexlify(args[2])
                except ValueError:
                    print "<KEYNO> is no a base 10 int"
                    help_auth()
                    continue
                except TypeError:
                    print "<KEY> is not a proper hex string"
                    help_auth()
                    continue
                
                if len(k) not in [8, 16]:
                    print "<KEY> is not 8 or 16 bytes long"
                    help_auth()
                    continue
                
                print LoyaltyCard(P_K_enc, P_K_shop, P_ca, cert, connection
                    ).authenticate_manual(keyno, k)

            elif command[0:len(select_cmd)] == select_cmd:
                args = command.split()
                def help_select():
                    print "USAGE: select <AID>"
                    print "  where <AID> is an integer"
                if len(args) != 2:
                    help_select()
                    continue

                try:
                    aid = int(args[1])
                except ValueError:
                    print "<KEYNO> is no a base 10 int"
                    help_select()
                    continue
                
                LoyaltyCard(P_K_enc, P_K_shop, P_ca, cert, connection
                    ).select_application(aid)

            else:
                print "Unknown command"
        else:
            print "Unknown command"
    connection == None or connection.disconnect()
        

def main(argv):
    print_welcome()
    read_keys()
    read_certificates()	
    main_loop()
    

if __name__ == "__main__":
    main(sys.argv[1:])

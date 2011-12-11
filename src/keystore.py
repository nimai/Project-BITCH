#!/usr/bin/env python

import ConfigParser, os.path
from binascii import unhexlify

class Keystore():

    def __init__(self, fname="keys/keystore.cfg"):
        self.config = ConfigParser.RawConfigParser()
        self.fname = fname
        if not os.path.exists(self.fname):
            self.__createFile()
        self.config.read(self.fname)

    def __createFile(self):
        defaultkey = unhexlify("00"*8)
        self.config.add_section('keys')
        self.setMasterKey(defaultkey)    
        

    def getMasterKey(self):
        if not os.path.exists(self.fname):
            self.__createFile()
        return self.config.get('keys','master')


    def setMasterKey(self, val):
        self.config.set('keys','master',val)
        with open(self.fname, 'wb') as f:
            self.config.write(f)

# vim: set ts=4 sts=4 sw=4 et:

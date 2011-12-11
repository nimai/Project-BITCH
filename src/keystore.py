#!/usr/bin/env python

import ConfigParser, os.path

class Keystore():

    def __init__(self, fname="keys/keystore.cfg"):
        self.config = ConfigParser.RawConfigParser()
        self.fname = fname
        self.masterkey = 1
        if not os.path.exists(self.fname):
            self.__createFile()
        self.config.read(self.fname)

    def __createFile(self):
        self.config.add_section('keys')
        self.setMasterKey(0)
        

    def getMasterKey(self):
        self.masterkey = self.config.get('keys','master')
        return self.masterkey


    def setMasterKey(self, val):
        if self.masterkey != val:
            self.config.set('keys','master',str(val))
            with open(self.fname, 'wb') as f:
                self.config.write(f)

# vim: set ts=4 sts=4 sw=4 et:

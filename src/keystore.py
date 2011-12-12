#!/usr/bin/env python

import ConfigParser, os.path
from ConfigParser import NoOptionError
import time
from binascii import hexlify,unhexlify

class Keystore():

    def __init__(self, fname="keys/keystore.cfg"):
        self.config = ConfigParser.RawConfigParser()
        self.fname = fname
        if not os.path.exists(self.fname):
            self.__createFile()
        self.config.read(self.fname)

    def __createFile(self):
        self.config.add_section('keys')
        with open(self.fname, 'wb') as f:
            self.config.write(f)

    def getMasterKey(self, tag_uid):
        """returns the master key associated to the given tag_uid
        @return: the key as an hexadecimal string or None if none was found"""
        if not os.path.exists(self.fname):
            self.__createFile()
            return None
        try:
            ret = self.config.get('keys',tag_uid)
        except NoOptionError:
            return None
        return ret


    def setMasterKey(self, tag_uid, key):
        """expects the key and the tag_uid as hexadecimal strings
        if a uid is already present, it will be backuped in a file named
        keystore_backup along with the associated key"""
        try:
            old_key = self.config.get('keys',tag_uid)
            print "Updating key for tag UID ({})".format(tag_uid)
            print "Backup of the old value is done in file keystore_backup"
            with open('keystore_backup', 'ab') as f:
                now = time.localtime()
                f.write(":".join([str(now.tm_year),  str(now.tm_mon),
                    str(now.tm_mday), str(now.tm_hour),  str(now.tm_min),
                    str(now.tm_sec), tag_uid, old_key]) + "\n")
        except NoOptionError:
            pass
        self.config.set('keys', tag_uid, key)
        with open(self.fname, 'wb') as f:
            self.config.write(f)

if __name__ == "__main__":
    k = Keystore()
    cur_key = k.getMasterKey("AABB")
    print "masterkey: ", cur_key
    if (cur_key is None):
        k.setMasterKey("AABB", "00"*8)
    else:
        k.setMasterKey("AABB", cur_key[:-1] + chr(ord(cur_key[-1]) + 1))
    print "newmasterkey: ",k.getMasterKey("AABB")


# vim: set ts=4 sts=4 sw=4 et:

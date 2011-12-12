#/usr/bin/env python

class BitchException(Exception):
    """base class for BITCH exceptions"""
    pass

class ImpossibleResponseRead(BitchException):
    """thrown when it is impossible to read the response"""
    pass

class ResponseError(BitchException):
    """raised when the two status words are not 0x90 0x0"""
    pass

class MultipleTagsOnReader(BitchException):
    """raised when they are multiple tags on the reader"""

class WrongKey(BitchException):
    """raised when something is wrong with a key"""

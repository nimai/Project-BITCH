#!/usr/bin/python
#Error codes for the sw2 status word of the Desfire response apdu

sw2_error_codes = {
0x00: 'OPERATION_OK',
0x0C: 'NO_CHANGES',
0x1C: 'ILLEGAL_COMMAND_CODE',
0x1E: 'INTEGRITY_ERROR (CRC or MAC does not match, padding invalid)',
0x40: 'NO_SUCH_KEY',
0x7E: 'LENGTH_ERROR (of the command)',
0x9D: 'PERMISSION_DENIED',
0x9E: 'PARAMETER_ERROR',
0xA0: 'APPLICATION_NOT_FOUND',
0xA1: 'APPLICATION_INTEGRITY_ERROR',
0xAE: 'AUTHENTICATION_ERROR',
0xAF: 'ADDITIONAL_FRAME (expected to be sent)',
0xBE: 'BOUNDARY_ERROR',
0xCA: 'COMMAND_ABORTED',
0xDE: 'DUPLICATE_ERROR',
0xF0: 'FILE_NOT_FOUND'}

#!/usr/bin/python
"""DesFire command meanings"""

desfire_cmd_meaning = {
# security related commands
0x0A: 'Authenticate ',
0x54: 'Change KeySettings ',
0x45: 'Get KeySettings ',
0xC4: 'Change Key ',
0x64: 'Get KeyVersion ',
# PICC level command',
0xCA: 'Create Application ',
0xDA: 'Delete Application ',
0x6A: 'Get Applications IDs ',
0x5A: 'Select Application ',
0xFC: 'FormatPICC ',
0x60: 'Get Version ',
# application level commands
0x6F: 'Get FileIDs ',
0xF5: 'Get FileSettings ',
0x5F: 'Change FileSettings ',
0xCD: 'Create StdDataFile ',
0xCB: 'Create BackupDataFile',
0xCC: 'Create ValueFile ',
0xC1: 'Create LinearRecordFile ',
0xC0: 'Create CyclicRecordFile ',
0xDF: 'DeleteFile ',
# data manipulation commands
0xBD: 'Read Data ',
0x3D: 'Write Data ',
0x6C: 'Get Value ',
0x0C: 'Credit ',
0xDC: 'Debit ',
0x1C: 'Limited Credit ',
0x3B: 'Write Record ',
0xBB: 'Read Records ',
0xEB: 'Clear RecordFile ',
0xC7: 'Commit Transaction ',
0xA7: 'Abort Transaction '
}





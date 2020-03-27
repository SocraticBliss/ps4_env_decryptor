#!/usr/bin/env python
'''

PS4 ENV File Decryptor by SocraticBliss(R)

Special Thanks to IDC for finding the Buffers/IV/Flag and implementation suggestions

... Oh and I guess Zecoxao as well

'''

from binascii import unhexlify as uhx, hexlify as hx
from Crypto.Cipher import AES

import struct
import sys

# Replace the 0's with the actual keys! :)

KEYS = {
     0x1 : '00000000000000000000000000000000', # beta_updatelist
     0x2 : '00000000000000000000000000000000', # timezone
     0x3 : '00000000000000000000000000000000', # system_log_config
     0x4 : '00000000000000000000000000000000', # system_log_unknown
     0x5 : '00000000000000000000000000000000', # bgdc
     0x6 : '00000000000000000000000000000000', # wctl
     0x7 : '00000000000000000000000000000000', # morpheus_updatelist
     0x8 : '00000000000000000000000000000000', # netev
     0xA : '00000000000000000000000000000000', # hid_config
     0xC : '00000000000000000000000000000000', # hidusbpower
     0xD : '00000000000000000000000000000000', # patch
     0xE : '00000000000000000000000000000000', # bgft
    0x11 : '00000000000000000000000000000000', # system_log_privacy
    0x13 : '00000000000000000000000000000000', # entitlementmgr
}

def aes_decrypt_cbc(key, iv, input):
    return AES.new(key, AES.MODE_CBC, iv).decrypt(input)

def main(argc, argv):
    if argc != 2:
        raise SystemExit('\nUsage: %s <file>' % argv[0])
    
    with open(argv[1], 'rb') as input, open(argv[1] + '.dec', 'wb') as output:
        
        data = input.read()
        
        id = struct.unpack('<I', data[0x8:0xC])[0]
        
        try:
            key = uhx(KEYS[id].replace(' ', ''))
        except:
            raise SystemExit('\nError: Invalid File!')
        
        size = struct.unpack('<Q', data[0x10:0x18])[0]
        iv   = data[0x20:0x30]
        
        message = data[0x150:0x150 + size]
        
        padding = 16 - (size % 16)
        message += chr(padding) * padding
        
        data = aes_decrypt_cbc(key, iv, message)
        output.write(data)
    
    print('\nSuccess!')

if __name__ == '__main__':
    main(len(sys.argv), sys.argv)
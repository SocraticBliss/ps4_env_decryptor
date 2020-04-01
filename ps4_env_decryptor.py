#!/usr/bin/env python
'''

PS4 ENV File Decryptor by SocraticBliss(R)

Special Thanks to IDC for finding the Buffers/IV/Flag and implementation suggestions
Huge thanks to Flatz for the proper decryption technique

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
     0x5 : '00000000000000000000000000000000', # bgdc_config
     0x6 : '00000000000000000000000000000000', # wctl_config
     0x7 : '00000000000000000000000000000000', # morpheus_updatelist
     0x8 : '00000000000000000000000000000000', # netev_config
     0x9 : '00000000000000000000000000000000', # gls_config
     0xA : '00000000000000000000000000000000', # hid_config
     0xC : '00000000000000000000000000000000', # hidusbpower
     0xD : '00000000000000000000000000000000', # patch_hmac_key
     0xE : '00000000000000000000000000000000', # bgft
    0x11 : '00000000000000000000000000000000', # system_log_privacy
    0x12 : '00000000000000000000000000000000', # webbrowser_xutil
    0x13 : '00000000000000000000000000000000', # entitlementmgr_config
    0x15 : '00000000000000000000000000000000', # jsnex_netflixdeckeys
    0x16 : '00000000000000000000000000000000', # party_config
}

# Big Thanks to Flatz
def aes_decrypt_cbc_cts(key, iv, data):
    result = ''
    data_size = len(data)
    
    if data_size == 0:
        return result
    
    context = AES.new(key, AES.MODE_ECB)
    num_data_left = data_size
    block_size = 16
    offset = 0
    
    while num_data_left >= block_size:
        input = data[offset:offset + block_size]
        output = context.decrypt(input)
        output = ''.join(chr(ord(output[i]) ^ ord(iv[i])) for i in xrange(block_size))
        num_data_left -= block_size
        offset += block_size
        result += output
        iv = input
    
    if num_data_left > 0 and num_data_left < block_size:
        input = data[offset - block_size:offset]
        output = context.encrypt(input)
        
        for i in xrange(num_data_left):
            result += chr(ord(data[offset + i]) ^ ord(output[i]))
    
    return result


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
        
        data = aes_decrypt_cbc_cts(key, iv, message)
        output.write(data)
    
    print('\nSuccess!')

if __name__ == '__main__':
    main(len(sys.argv), sys.argv)
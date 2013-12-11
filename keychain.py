# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4

"""keychain.py: A Simple key chain implementation for Safe."""
__author__      = "Wathsala Vithanage"
__email__       = "wathsala@princeton.edu"
__copyright__   = "Copyright 2013, Safe Project"
__credits__     = ["Andrew Werner", "Stephen Lin"]
__license__     = "Apache"
__version__     = "0.1"


"""
    This is a simple keychain implementation for Safe.
    Safe Keychain is simply stored in a file according 
    to the following format.
    +------------------+------------------+-------------------------+-------------------------+
    |Certificate Length|Private Key Length|Namespace Certificate PEM|Encrypted Private Key PEM|
    +------------------+------------------+-------------------------+-------------------------+
"""

import mmap
import struct
import string
import traceback
from os import path, stat
from ctypes import *
from Crypto.Protocol.KDF import PBKDF2
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES

class KeyChain:
    MASTER_KEY_PAIR = 0
    ERROR_KEY_EXIST = 1
    SUCCESS         = 0

    def __init__(self, keychain_path, name, password):
        '''
        Keychain constructor, this initializes the keychain.
        '''
        self.password = password
        self.keychain_path = keychain_path
        self.kc_key = PBKDF2(password, name, 32, 5000)
        self.kc_file = open(self.keychain_path, 'a+')
        st = stat(self.keychain_path)


    def read_keychain(self):
        '''
        Return the certficate and the private key
        '''
        try:
            kc_mm = mmap.mmap(self.kc_file.fileno(), 0, mmap.MAP_PRIVATE, 
                    mmap.PROT_READ | mmap.PROT_WRITE)
        except (ValueError, TypeError) as e:
            return None
        _offset = 0
        cert_len = struct.unpack('I', kc_mm[_offset:_offset+4])[0]
        _offset += 4
        key_len  = struct.unpack('I', kc_mm[_offset:_offset+4])[0]
        _offset += 4
        cert_pem = struct.unpack(str(cert_len)+'s', kc_mm[_offset:_offset+cert_len])[0]
        _offset += cert_len
        key_pem  = struct.unpack(str(key_len)+'s', kc_mm[_offset:_offset+key_len])[0]
        return cert_pem, key_pem


    def write_keychain(self, certificate, priv_key):
        '''
        Write certificate of and the KeyChain.
        '''
        #traceback.print_stack()
        rec = self.read_keychain()
        if rec is not None:
            return -KeyChain.ERROR_KEY_EXIST
        cert_len = len(certificate)
        key_len  = len(priv_key)
        _offset = 0
        self.kc_file.seek(_offset,0)
        self.kc_file.write(struct.pack('I', cert_len))
        self.kc_file.write(struct.pack('I', key_len))
        self.kc_file.write(certificate)
        self.kc_file.write(priv_key)
        self.kc_file.flush()
        return KeyChain.SUCCESS


    def encrypt_key(self, secret_key):
        '''
        Encrypt the secret_key with keychain_key using AES.MODE_CBC
        with an initialization vector...
        We do not need padding as we always deal with a string that 
        always will have a length of multiple of 16, 24, 32.
        '''

        #TODO: Implement encryption correctly...
        encrypted_key = None
        cipher = AES.new(self.kc_key)
        encrypted_key = cipher.encrypt(secret_key)
        return encrypted_key

    def decrypt_key(self, keychain_key, encrypted_key):
        secret = None
        cipher = AES.new(self.kc_key)
        secret = cipher.decrypt(encrypted_key)
        return secret

    def generate_RSA(self, bits=2048):
        '''
        Generate an RSA keypair with an exponent of 65537 in DER format
        param: bits The key length in bits
        Return private key and public key
        '''
        new_key = RSA.generate(bits, e=65537)
        public_key = new_key.publickey().exportKey("DER")
        private_key = new_key.exportKey("DER")
        return public_key, private_key


''' Test KeyCahin class
kc = KeyChain("/tmp", "wathsala", "1234")
ret = kc.write_keychain("fsfasfafsadgsd", "sfdf")
if ret == KeyChain.SUCCESS:
    print "Success"
else:
    print ret
device_data = kc.read_keychain()
print "CERTIFICATE >>> "+str(device_data[0])
print "PRIVATE_KEY >>> "+str(device_data[1])
'''


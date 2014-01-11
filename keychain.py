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
import hashlib
from base64 import b64encode, b64decode
from os import path, stat
from ctypes import *
from Crypto import Random
from Crypto.Hash import SHA
from Crypto.Signature import PKCS1_PSS
from Crypto.Protocol.KDF import PBKDF2
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from cStringIO import StringIO
from subprocess import Popen, PIPE

def pubkey_from_cert(cert_pem):
    """ Invokes openssl to extract the public key from the certificate"""
    ossl = Popen(['openssl','x509','-pubkey','-noout'] , stdout=PIPE, stderr=PIPE, stdin=PIPE)
    (stdout,_) = ossl.communicate(cert_pem)
    lines = stdout.strip().split('\n')
    res = ""
    if "BEGIN PUBLIC KEY" not in lines[0] or "END PUBLIC KEY" not in lines[-1]:
        raise AttributeError("Could not extract key from x509 certificate in PEM mode")
    else:
        res = stdout
    return res

def encrypt_with_cert(cert_pem, message):
    pubkey_pem = pubkey_from_cert(cert_pem)
    pubkey = RSA.importKey(pubkey_pem)
    pkcs = PKCS1_OAEP.new(pubkey)
    return pkcs.encrypt(message)

def decrypt_with_privkey(privkey_pem, message):
    privkey = RSA.importKey(privkey_pem)
    pkcs = PKCS1_OAEP.new(privkey)
    return pkcs.decrypt(message)

def sign_with_privkey(privkey_pem, message):
    privkey = RSA.importKey(privkey_pem)
    h = SHA.new()
    h.update(message)
    signer = PKCS1_PSS.new(privkey)
    return b64encode(signer.sign(h))

def verify_signature(cert_pem, message, sig):
    pubkey_pem = pubkey_from_cert(cert_pem)
    pubkey = RSA.importKey(pubkey_pem)
    h = SHA.new()
    h.update(message)
    verifier = PKCS1_PSS.new(pubkey)
    return verifier.verify(h, b64decode(sig))

def AES_encrypt(serialization, key):
    """returns a base64 encoded AES encrypted copy of serialization"""
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    msg = iv + cipher.encrypt(serialization)
    return b64encode(msg)

def AES_decrypt(encrypted, key):
    """returns a base64 encoded AES encrypted copy of serialization"""
    msg = b64decode(encrypted)
    iv = msg[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CFB, iv)
    return cipher.decrypt(msg[AES.block_size:])

def derive_key(secret):
    #Stretch keys over SHA1 hash of password 10 times.
    key = '';
    for i in xrange(10):
        sha256_str = hashlib.sha256()
        sha256_str.update(key + secret)
        key = sha256_str.digest()
    return key


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
        self.key_enc_key = derive_key(self.password)
        stat(self.keychain_path)

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
        key_pem  = AES_decrypt(struct.unpack(str(key_len)+'s', kc_mm[_offset:_offset+key_len])[0], self.key_enc_key)
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
        self.kc_file.write(AES_encrypt(priv_key, self.key_enc_key))
        self.kc_file.flush()
        return KeyChain.SUCCESS

    def update_keychain(self, cert):
        rec = self.read_keychain()
        key = rec[1]
        key_len = len(key)
        cert_len = len(cert)
        self.kc_file.seek(0,0)
        self.kc_file.truncate(0)
        self.kc_file.write(struct.pack('I', cert_len))
        self.kc_file.write(struct.pack('I', key_len))
        self.kc_file.write(cert)
        #Encrypt the key before writing it to storage.
        self.kc_file.write(AES_encrypt(key, self.key_enc_key))
        self.kc_file.flush()
        return KeyChain.SUCCESS

    def encrypt_key(self, secret_key):
        '''
        Encrypt the secret_key with keychain_key using AES.MODE_CBC
        with an initialization vector...
        '''
        encrypted_key = None
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

    def encrypt(self, message):
        """ pubkey encrypts the message """
        cert_pem = self.read_keychain()[0]
        return encrypt_with_cert(cert_pem, message)

    def decrypt(self, message):
        """ uses the private key to decrypt pubkey encrypted message """
        privkey_pem = self.read_keychain()[1]
        return decrypt_with_privkey(privkey_pem, message)

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

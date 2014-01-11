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
    print b64encode(key)
    """returns a base64 encoded AES encrypted copy of serialization"""
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    msg = iv + cipher.encrypt(serialization)
    return b64encode(msg)

def AES_decrypt(encrypted, key):
    print b64encode(key)
    """returns a base64 encoded AES encrypted copy of serialization"""
    msg = b64decode(encrypted)
    iv = msg[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CFB, iv)
    return cipher.decrypt(msg[AES.block_size:])

def derive_key(secret):
    sha256_str = hashlib.sha256()
    sha256_str.update(secret)
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
        encrypted_key = AES_encrypt(priv_key, self.key_enc_key)
        cert_len = len(certificate)
        key_len  = len(encrypted_key)
        _offset = 0
        self.kc_file.seek(_offset,0)
        self.kc_file.write(struct.pack('I', cert_len))
        self.kc_file.write(struct.pack('I', key_len))
        self.kc_file.write(certificate)
        self.kc_file.write(encrypted_key)
        self.kc_file.flush()
        return KeyChain.SUCCESS

    def update_keychain(self, cert):
        rec = self.read_keychain()
        key = rec[1]
        encrypted_key = AES_encrypt(priv_key, self.key_enc_key)
        key_len = len(encrypted_key)
        cert_len = len(cert)
        self.kc_file.seek(0,0)
        self.kc_file.truncate(0)
        self.kc_file.write(struct.pack('I', cert_len))
        self.kc_file.write(struct.pack('I', key_len))
        self.kc_file.write(cert)
        #Encrypt the key before writing it to storage.
        self.kc_file.write(encrypted_key)
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
kc = KeyChain("/tmp/test.kc", "wathsala", "1234")
priv_key = "1kAFRoFPN41VfpItASjNN3gjLe0YhHonysH22A1VVzb8J+ZtMU7OfO7NEswtcF3DLG+6oeG9sLbgyzC45s/QO3vdmQSGnnYbiIR3xD+lgTE4uoeMz54n6YCJEhO+o5Vb49jl/p9YO5MQx6ghOAMVXuqkoAcZFFqsGAguMCirkrDmjEqjbR/ntoxEv7tbe8gr70C1uwV/PWiyinAhIgXVaNKI6G41HTeBDRSIXeMmpumUPyZDXhxgsF1zQWlXiCF+fYal8KlIQ3qx+Jc7MD4cMjFXcjaAw5wIxnjR6Tc2cIHtuSxBi4ZghwVc1/Caas5p1vSDGQOOTZUT5DLQhwMt0Q+qt+RoqYeTgSRuU2Xh5yKZOXZ/ag69wTKJhzDmEy6YxL+2Nfi5JpXX3iGECahwbmf8ZANV1rH/AtrHQ9CbAx0a0SIwL9WZbOCtUHwlXRV271NscUnHbJAw8QICpqPwZ8AzvESqjFz/3g2YYV7+L8rVz6EMRqPJ7ceVSCqu0L3Ap+f5wTG07R7XIEKCoKBcaKuAboE+Cr3Ypw2rGt7Fep2CDBfyd1Q8fvjkM6C8tO7SAmMwpLuyv0Qanx31DNzhOA1u8ffqPXEfDBVGpyAB9SBYmNOYVChGJcROpdwzwdjKIzqj0HtIW7EaCRgClCBE0tsLo8tFuSSxIoFtsO/E3ypw5MI2zI89vfsSuMbbrQDXKE48+onaUrnTzXvmLZEo7NqWQ/dFPPQ1+B9NMyCnr+FXe58tWgjzn+z1feskG2Zp7FlltI2BQViCeqio++L7smZtQ8AOiCqcF1Awqkw8w/SU58oQwaPo6Kc9PkqWGZw2smOPfCq6PpE8HVe3IWLCVKe3sfZHdjCSUzCeOkzmf0R/WoyW5a8iObwTQtVezho9LC87LzmXXJw4qU51evhiZQC6BSWxfC2IRRHRKOlcBxJhSvkL1AX+6SGzjNTv9DZjZfMv7A2LWaDnuW+Dov+xtGMLujtNnCuN59pUEZUp1pdkrU2T7afJi2fxnobQPBpX7qy5w94EAIOV5yJkAGLLh65YS8EoDgiVRG0fk9mgPDUIAcIVgTEcLtyQ9xN0QBcj/Tq+tNsdXR5Ha79YTkexMJVIN76EIt0FLgGf+p5qEdcbuJQg3nUR6/u60CHvjKJ6QiTv0Axc46xraI97A/O3KUZRQn+/dAIQci7r7DGjqVrZLQbCLHbe/DSsoyQObhI2waF4mo7+xKxA++Gal5w+OZ48aO0="

cert = "1kAFRoFPN41VfpItASjNN3gjLe0YhHonysH22A1VVzb8J+ZtMU7OfO7NEswtcF3DLG+6oeG9sLbgyzC45s/QO3vdmQSGnnYbiIR3xD+lgTE4uoeMz54n6YCJEhO+o5Vb49jl/p9YO5MQx6ghOAMVXuqkoAcZFFqsGAguMCirkrDmjEqjbR/ntoxEv7tbe8gr70C1uwV/PWiyinAhIgXVaNKI6G41HTeBDRSIXeMmpumUPyZDXhxgsF1zQWlXiCF+fYal8KlIQ3qx+Jc7MD4cMjFXcjaAw5wIxnjR6Tc2cIHtuSxBi4ZghwVc1/Caas5p1vSDGQOOTZUT5DLQhwMt0Q+qt+RoqYeTgSRuU2Xh5yKZOXZ/ag69wTKJhzDmEy6YxL+2Nfi5JpXX3iGECahwbmf8ZANV1rH/AtrHQ9CbAx0a0SIwL9WZbOCtUHwlXRV271NscUnHbJAw8QICpqPwZ8AzvESqjFz/3g2YYV7+L8rVz6EMRqPJ7ceVSCqu0L3Ap+f5wTG07R7XIEKCoKBcaKuAboE+Cr3Ypw2rGt7Fep2CDBfyd1Q8fvjkM6C8tO7SAmMwpLuyv0Qanx31DNzhOA1u8ffqPXEfDBVGpyAB9SBYmNOYVChGJcROpdwzwdjKIzqj0HtIW7EaCRgClCBE0tsLo8tFuSSxIoFtsO/E3ypw5MI2zI89vfsSuMbbrQDXKE48+onaUrnTzXvmLZEo7NqWQ/dFPPQ1+B9NMyCnr+FXe58tWgjzn+z1feskG2Zp7FlltI2BQViCeqio++L7smZtQ8AOiCqcF1Awqkw8w/SU58oQwaPo6Kc9PkqWGZw2smOPfCq6PpE8HVe3IWLCVKe3sfZHdjCSUzCeOkzmf0R/WoyW5a8iObwTQtVezho9LC87LzmXXJw4qU51evhiZQC6BSWxfC2IRRHRKOlcBxJhSvkL1AX+6SGzjNTv9DZjZfMv7A2LWaDnuW+Dov+xtGMLujtNnCuN59pUEZUp1pdkrU2T7afJi2fxnobQPBpX7qy5w94EAIOV5yJkAGLLh65YS8EoDgiVRG0fk9mgPDUIAcIVgTEcLtyQ9xN0QBcj/Tq+tNsdXR5Ha79YTkexMJVIN76EIt0FLgGf+p5qEdcbuJQg3nUR6/u60CHvjKJ6QiTv0Axc46xraI97A/O3KUZRQn+/dAIQci7r7DGjqVrZLQbCLHbe/DSsoyQObhI2waF4mo7+xKxA++Gal5w+OZ48aO0="

kc.write_keychain(cert, priv_key);
dec_priv_key = kc.read_keychain()[1]
if priv_key == dec_priv_key :
    print "OK"
'''

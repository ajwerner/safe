"""
This is a simple keychain implementation for Safe.
Safe Keychain is simply stored in a file according to the following format.
+-------------------------+---------+-------------------------------------------------------------------+
|Master Key<Pub, Enc-Priv>|Dev-Table|Dev-1 Pub-Key Len|Dev-1 Pub-Key|...|Dev-N Pub-Key Len|Dev-n Pub-Key|
+-------------------------+---------+-------------------------------------------------------------------+

Dev-Table supports 65535 devices

+---------------------------+
|Offset of Dev-1 Pub-Key Len|
+---------------------------+
|Offset of Dev-2 Pub-Key Len|
+---------------------------+
|	    ....            |
+---------------------------+
|Offset of Dev-N Pub-Key Len|
+---------------------------+
"""

import mmap
import os
import struct
from ctypes import *
from Crypto.Protocol.KDF import PBKDF2
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES

class KeyChain:
	RSA_key_len = 256
	MASTER_KEY_PAIR = 0
	DEVICE_KEY_PAIR = 1
	NR_DEVICES	= 65535
	ERROR_EMPTY_KEYCHAIN = 1
	ERROR_DEVICE_EXISTS  = 2

	def __init__(self, path, namespace, password):
		'''
		Keychain constructor, this initializes the keychain.
		'''
		self.namespace = namespace
		self.password = password
		self.keychain_path = path+"/"+namespace
		self.kc_key = PBKDF2(password, namespace, 32, 5000)
		self.kc_file = open(self.keychain_path, "w+b")
		st = os.stat(self.keychain_path)
		if st.st_size == 0:
			master_keypair = self.generate_RSA(KeyChain.RSA_key_len * 8)
			self.kc_file.write(struct.pack("i", len(master_keypair[0])))
			self.kc_file.write(struct.pack(str(len(master_keypair[0]))+"s", 
							master_keypair[0]))
			#Encrypt the private key of the master key.
			#encrypted_priv_key = self.encrypt_key(master_keypair[0])
			self.kc_file.write(struct.pack("i", len(master_keypair[1])))
			self.kc_file.write(struct.pack(str(len(master_keypair[1]))+"s", 
							master_keypair[1]))
			#Write device table
			DevTable = c_int64 * KeyChain.NR_DEVICES
			dt = DevTable()
			for i in range(KeyChain.NR_DEVICES):
				dt[i] = 0
			self.kc_file.write(struct.pack(
					str(8 * KeyChain.NR_DEVICES)+"s", buffer(dt)[:]))
			self.kc_file.flush()


	def read_keychain(self, key_type, dev_id=0):
		'''
		This method is used to read values from the keychain.
		1) Return the tuple master public/private(encrypted) keys.
		2) Return the master key of device with the id dev_id.
		'''
		kc_mm = mmap.mmap(self.kc_file.fileno(), 0, mmap.MAP_PRIVATE, 
					mmap.PROT_READ | mmap.PROT_WRITE)
		if kc_mm is None:
			return None
		#Read master public key length
		_offset = 0
		master_pubkey_len = struct.unpack('I', kc_mm[_offset:4])[0]

		#Read master public key (offset = 4)
		_offset += 4
		master_pubkey = struct.unpack(str(master_pubkey_len)+'s', kc_mm[_offset:
			_offset + master_pubkey_len])[0]

		#Read master private key length (offset = 4 + master_pubkey_len)
		_offset += master_pubkey_len 
		master_privkey_len = struct.unpack('I', kc_mm[_offset:_offset+4])[0]

		#Read master private key (offset = 4 + master_pubkey_len + 4)
		_offset += 4
		master_privkey = struct.unpack(str(master_privkey_len)+'s', kc_mm[_offset:
			_offset + master_privkey_len])[0]
		if key_type == KeyChain.MASTER_KEY_PAIR:
			return master_pubkey, master_privkey
		#Find the location of the device key
		_offset += master_privkey_len
		_offset += dev_id * 4
		device_loc = struct.unpack('I', kc_mm[_offset:(_offset + 4)])[0]
		if device_loc == 0:
			return None
		key_len = struct.unpack('I', kc_mm[device_loc: (device_loc+4)])[0]
		key = struct.unpack(str(key_len)+'s', kc_mm[(device_loc + 4): 
						(device_loc + 4 + key_len)])
		kc_mm.close()
		return key, None
	
	def write_keychain(self, dev_id, public_key, priv_key):
		'''
		Write public key of device dev_id to the KeyChain.
		'''
		master_rec = self.read_keychain(KeyChain.MASTER_KEY_PAIR)
		if master_rec is None:
			return -KeyChain.ERROR_EMPTY_KEYCHAIN
		block = self.read_keychain(KeyChain.DEVICE_KEY_PAIR, dev_id)
		if block is not None:
			return -KeyChain.ERROR_DEVICE_EXISTS
		_offset = len(master_rec[0]) + len(master_rec[1]) + 8
		#Update the table
		_offset += dev_id*4
		st = os.stat(self.keychain_path)
		self.kc_file.seek(_offset, 0)
		self.kc_file.write(struct.pack('i', st.st_size))
		#Append the key
		pubkey_len = len(public_key)
		self.kc_file.seek(0, 2);
		self.kc_file.write(struct.pack("i", pubkey_len))
		self.kc_file.write(struct.pack(str(pubkey_len)+"s", public_key))
		key = struct.unpack(str(pubkey_len)+'s', public_key)
		self.kc_file.flush()
		return 0

	def encrypt_key(self, secret_key):
		'''
		Encrypt the secret_key with keychain_key using AES.MODE_CBC
		with an initialization vector...
		We do not need padding as we always deal with a string that 
		always will have a length of multiple of 16, 24, 32.
		'''
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
master_data = kc.read_keychain(KeyChain.MASTER_KEY_PAIR)
ret = kc.write_keychain(10, master_data[0], master_data[1])
if ret == 0:
	print "Success"
else:
	print ret
device_data = kc.read_keychain(KeyChain.DEVICE_KEY_PAIR, 10)
print "Public Key>>> "+str(device_data[0])
'''


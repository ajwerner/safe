# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4

"""device.py: A Simple device representation for Safe."""
__author__      = "Wathsala Vithanage"
__email__       = "wathsala@princeton.edu"
__copyright__   = "Copyright 2013, Safe Project"
__credits__     = ["Andrew Werner", "Stephen Lin"]
__license__     = "Apache"
__version__     = "0.1"

import time
import json
import os
from OpenSSL    import crypto, SSL
from time       import gmtime, mktime
from X509       import X509, X509Error
from keychain   import KeyChain

class DeviceError():
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return str(self.value)

class DeviceEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Device):
            return obj.__dict__
        else:
            return json.JSONEncoder.default(self, obj)
        
class DeviceDecoder(json.JSONDecoder):
    def decode(self, json_str):
        try:
            dec_str = json.loads(json_str)
        except ValueError as e:
            raise e
        if dec_str:
            return Device(dec_str['dev_id'], dec_str['dev_name'], 
                        dec_str['app_obj'], dec_str['int_ts'])
        else:
            return None

class Device():
    def __init__(self, dev_id, dev_name, app_obj, ts=-1):
        if dev_id < 0 or dev_id > 65535:
            raise DeviceError("Bad Device ID (dev_id="+str(dev_id)+")")
        self.dev_id = dev_id
        self.dev_name = dev_name
        self.app_obj = app_obj
        if ts == -1:
            self.int_ts = time.time()
        else:
            self.int_ts = ts

    #def join_namespace(self, ns_name, connection):
    def join_namespace(self, ns_name):
        key_chain_name = str(self.dev_id)+"."+ns_name+".kc"
        if os.path.exists("/tmp/"+key_chain_name):
            raise X509Error("Certificate exists: "+key_chain_name)
        #Generate private/public key pair
        pkey = crypto.PKey()
        pkey.generate_key(crypto.TYPE_RSA, 1024)
        #TODO: Read these values from the configyration file
        country    = "US"
        state      = "NJ"
        city       = "Princeton"
        kc_passwd  = "1234"
        x509 = X509(str(self.dev_id), pkey, ns_name, country, state, 
                    city)
        x509.forge_certificate(False)
        rec = x509.get_PEM_certificate()
        cert_pem = rec[0]
        key_pem  = rec[1]
        self.certx = cert_pem 
        #TODO:
        #This method needs a connection as an input to it.
        #We will send the cert_pem to the NS node and get it signed. 
        #...
        #signed_cert_pem = connection.sign_cert(cert_pem)
        #...
        #Now write signed_cert_pem and key_pem to the device keychain
        signed_cert_pem = cert_pem #delete this once we have a connection
        kc = KeyChain("/tmp", key_chain_name, kc_passwd)
        if kc.write_keychain(signed_cert_pem, key_pem) < 0:
            raise X509Error("Certificate exists: "+key_chain_name)

    def __str__(self):
        return self.dev_name+"#"+str(self.dev_id)+"@"+str(self.int_ts)

    def __hash__(self):
        return self.dev_id

    def __cmp__(self, other):
        if self.dev_id < other.dev_id:
            return -1
        elif self.dev_id == other.dev_id:
                return 0
        else:
            return 1


'''Test Device class
try:
    dev = Device(10, "iPhone", None)
    try:
        dev.join_namespace("wathsala")
    except X509Error as e:
        print "Certificate for this device already exists!"
    print dev
    json_dev = json.dumps(dev, cls=DeviceEncoder)
    #print json_dev
    dev2 = json.loads(json_dev, cls=DeviceDecoder)
    print dev2
except DeviceError as e:
    print "Error"
'''

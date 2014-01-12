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
import tofu
import copy
from os                 import path
from OpenSSL            import crypto, SSL
from time               import gmtime, mktime
from X509               import X509, X509Error
from keychain      import KeyChain
from Crypto.PublicKey   import RSA
from Crypto.Cipher      import PKCS1_OAEP

class DeviceError():
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return str(self.value)

class SafeDeviceEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, SafeDevice):
            obj_dict = copy.deepcopy(obj.__dict__)
            if '_conf' in obj_dict:
                del obj_dict['_conf']
            if 'keychain' in obj_dict:
                del obj_dict['keychain']
            return obj_dict
        else:
            return json.JSONEncoder.default(self, obj)
        
class SafeDeviceDecoder(json.JSONDecoder):
    def decode(self, json_str):
        try:
            dec_dict = json.loads(str(json_str))
        except ValueError as e:
            raise e
        if dec_dict is not None:
            return SafeDevice(**dec_dict)
        else:
            return None

class SafeDevice():
    DECODER = SafeDeviceDecoder
    ENCODER = SafeDeviceEncoder

    def __init__(self, dev_id=None, dev_name=None, app_obj=None, int_ts=-1, ns_name=None, cert_pem=None):
        # TODO: probably do validation here
        self.dev_id = dev_id
        self.dev_name = dev_name
        self.app_obj = app_obj
        self.ns_name = ns_name
        if int_ts == -1:
            self.int_ts = time.time()
        else:
            self.int_ts = int_ts
        self.cert_pem = cert_pem

    def __str__(self):
        return self.dev_name+"#"+str(self.dev_id)+"@"+str(self.int_ts)

    def __hash__(self):
        return hash(self.dev_id)

    def __cmp__(self, other):
        return cmp(self.dev_id, other.dev_id)

'''Test Device class

try:
    dev = Device(10, "iPhone", None)
    try:
        dev.join_namespace("wathsala")
    except X509Error as e:
        print "Certificate for this device already exists!"
    #print dev
    dev.sync_local_storage()
    json_dev = json.dumps(dev, cls=DeviceEncoder)
    #print json_dev
    dev2 = json.loads(json_dev, cls=DeviceDecoder)a
    print dev2
    dev3 = Device.load_device()
    print dev3
except DeviceError as e:
    print "Error"
'''

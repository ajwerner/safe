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
from os             import path
from configuration  import Configuration
from OpenSSL        import crypto, SSL
from time           import gmtime, mktime
from X509           import X509, X509Error
from keychain       import KeyChain

class DeviceError():
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return str(self.value)

class DeviceEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Device):
            obj_dict = copy.deepcopy(obj.__dict__)
            if '_conf' in obj_dict:
                del obj_dict['_conf']
            if 'keychain' in obj_dict:
                del obj_dict['keychain']
            return obj_dict
        else:
            return json.JSONEncoder.default(self, obj)
        
class DeviceDecoder(json.JSONDecoder):
    def decode(self, json_str):
        try:
            dec_dict = json.loads(str(json_str))
        except ValueError as e:
            raise e
        if dec_dict is not None:
            return Device(dec_dict['dev_id'], dec_dict['dev_name'], dec_dict['app_obj'], 
                            conf=None, ts=dec_dict['int_ts'], ns_name=dec_dict['ns_name'], 
                            cert=dec_dict['cert_pem'])
        else:
            return None

class Device():
    DECODER = DeviceDecoder
    ENCODER = DeviceEncoder

    def __init__(self, dev_id, dev_name, app_obj, conf=None, ts=-1, ns_name=None, cert=None):
        if dev_id < 0 or dev_id > 65535:
            raise DeviceError("Bad Device ID (dev_id="+str(dev_id)+")")
        self.dev_id = dev_id
        self.dev_name = dev_name
        self.app_obj = app_obj
        self.ns_name = ns_name
        self._conf = conf
        if conf is not None:
            self.keychain = conf.dev_keychain
            self.cert_pem = self.keychain.read_keychain()[0]
        else:
            self.cert_pem = cert
        print self._conf
        if ts == -1:
            self.int_ts = time.time()
        else:
            self.int_ts = ts

    @classmethod
    def load_device(cls, conf):
        with open(conf.dev_conf, "r") as json_in:
            dev = json.load(json_in, cls=DeviceDecoder)
            return cls(dev.dev_id, dev.dev_name, dev.app_obj, 
                    conf, dev.int_ts, dev.ns_name, dev.cert_pem)


    def join_namespace(self, ns_name, connection):
    #def join_namespace(self, ns_name):
        #Generate private/public key pair
        '''pkey = crypto.PKey()
        pkey.generate_key(crypto.TYPE_RSA, 1024)
        #TODO: Read these values from the configyration file
        country    = "US"
        state      = "NJ"
        city       = "Princeton"
        kc_passwd  = "1234"
        x509 = X509(str(self.dev_id), pkey, ns_name, country, state, 
                    city)
        x509.forge_certificate(False)
        x509.sign_certificate(None)
        rec = x509.get_PEM_certificate()
        cert_pem = rec[0]
        key_pem  = rec[1]
        self.cert_pem = cert_pem 
        self.ns_name = ns_name
        keychain_name = str(self.dev_id)+"."+self.ns_name'''
        #TODO:
        #This method needs a connection as an input to it.
        #We will send the cert_pem to the NS node and get it signed. 
        dev_json_str = json.dumps(self, cls=Device.ENCODER)
        connection.send(dev_json_str)
        print "Sent...."
        signed_cert_pem = connection.receive()
        print ">>>> "+signed_cert_pem
        #...
        #Now write signed_cert_pem and key_pem to the device keychain
        #signed_cert_pem = cert_pem #delete this once we have a connection
        self.keychain.update_keychain(signed_cert_pem)

    def sync_local_storage(self):
        if self.ns_name is not None:
            with open(self._conf.dev_conf, "w") as json_out:
                json.dump(self, json_out, cls=DeviceEncoder)
        else:
            raise DeviceError("Device "+str(self.dev_id)+" is not in any namespace")

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
    #print dev
    dev.sync_local_storage()
    json_dev = json.dumps(dev, cls=DeviceEncoder)
    #print json_dev
    dev2 = json.loads(json_dev, cls=DeviceDecoder)
    print dev2
    dev3 = Device.load_device()
    print dev3
except DeviceError as e:
    print "Error"
'''

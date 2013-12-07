# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4

"""namespace.py: A Simple namespace implementation for Safe."""
__author__      = "Wathsala Vithanage"
__email__       = "wathsala@princeton.edu"
__copyright__   = "Copyright 2013, Safe Project"
__credits__     = ["Andrew Werner", "Stephen Lin"]
__license__     = "Apache"
__version__     = "0.1"

"""
    1) Provides a primary storage for information of devices owned by the 
       namespace owner.
       Data will be stored according to the JSON format given below.
       {
            "dev_id":       "16-bit ID",
            "dev_name":     "iPhone",
            "int_ts":       "7/20/2013",
            "app_data":     "{Name: Wathsala Vithanage},
                             {Addr: 35, Olden St. Princeton, NJ, 08540}"
       }
    2) Provides a primary storage for information of other namespaces
       that are trusted by this namespace. (alice.bob Alice's namespace refer 
       to bob's namespace)
    3) Do not cache information about devices owned by trusted namespaces.
       Always download the device vector of the trusted namespace before
       name binding happens. (alice.bob.iphone is not cached, always request
       a device list from alice.bob so that we are aware of key revoked device
       keys.
    Note: All primary storages are cacheable on Amazon S3.
"""
import os
import json
import logging

from device import Device
from device import DeviceEncoder
from device import DeviceDecoder
from device import DeviceError

from peer_ns import PeerNS
from peer_ns import PeerNSEncoder
from peer_ns import PeerNSDecoder
from peer_ns import PeerNSError

from X509 import X509, X509Error

#Setup logging...
logging.basicConfig(format='%(levelname)s:%(message)s')

class Namespace:
    def __init__(self, ns_name, dev_list, ns_list):
        self.dev_list = dev_list
        self.ns_list = ns_list
        self.ns_name = ns_name
        self.devl_fd = open(self.dev_list, "a+")
        self.nsl_fd = open(self.ns_list, "a+")

        self.dev_list_obj = None
        self.dev_set = set()

        self.ns_list_obj = None
        self.ns_set = set()
        
        #Parse the device list and pack them in a set
        try:
            self.dev_list_obj = json.load(self.devl_fd)
            for dev_dict in self.dev_list_obj:
                dev_json = json.dumps(dev_dict)
                self.dev_set.add(json.loads(dev_json, cls=DeviceDecoder))
        except ValueError as e:
            logging.warning("%s:%s",self.dev_list, str(e))

        #Parse the namespace list and pack them in a set
        try:
            self.ns_list_obj = json.load(self.nsl_fd)
            for ns_dict in self.ns_list_obj:
                ns_json = json.dumps(ns_dict)
                self.ns_set.add(json.loads(ns_json, cls=PeerNSDecoder))
        except ValueError as e:
            logging.warning("%s:%s", self.ns_list, str(e))


    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.sync_local_storage()
        self.devl_fd.close()
        self.nsl_fd.close()
    
    def get_device_list(self):
        return json.dumps(list(self.dev_set), cls=DeviceEncoder)
    
    def get_peer_ns_list(self):
        return json.dumps(list(self.ns_set), cls=PeerNSEncoder)

    def sync_local_storage(self):
        self.devl_fd.truncate(0)
        dev_list_json = json.dumps(list(self.dev_set), cls=DeviceEncoder)
        self.devl_fd.write(dev_list_json)
        self.nsl_fd.truncate(0)
        json.dump(list(self.ns_set), self.nsl_fd, cls=PeerNSEncoder)

    def _add_device(self, device):
        self.dev_set.add(device)

    #def add_device(self, connection)
    def add_device(self, dev): #Remove dev when switching to above prototype
        #read the device out from the connection...
        #dev = json.loads(dev_str, cls=DeviceDecoder)
        ucert_pem = dev.cert_pem
        x509 = X509.load_certificate_from_keychain(self.ns_name)
        cert_key = x509.get_certificate()
        cert = cert_key[0]
        key  = cert_key[1]
        dev_x509 = X509.load_certifacate_from_PEM(ucert_pem)
        dev_x509.sign_certificate(cert, key)
        dev.cert_pem = dev_x509.get_PEM_certificate()[0]
        print dev.cert_pem
        self._add_device(dev)
        #write the signed certificate dev.cert_pem back to connection 

    def _remove_device(self, device):
        self.dev_set.remove(device)

    def _add_peer_namespace(self, pns):
        self.ns_set.add(pns)

    def _remove_peer_namespace(self, pns):
        self.ns_set.remove(pns)

'''Test Namespace

from OpenSSL import crypto

with Namespace("wathsala", "/tmp/dev_list", "/tmp/ns_list") as ns:
    dev0 = Device(10, "iPhone", None)
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 1024)
    dev0.join_namespace("wathsala")
    ns.add_device(dev0)

    ns.sync_local_storage()
'''

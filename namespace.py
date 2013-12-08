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
import boto
import logging

from configuration import Configuration

from boto import dynamodb2, iam

from device import Device, DeviceEncoder, DeviceDecoder, DeviceError
from peer_ns import PeerNS, PeerNSEncoder, PeerNSDecoder, PeerNSError
from X509 import X509, X509Error
from OpenSSL import crypto


#Setup logging...
logging.basicConfig(format='%(levelname)s:%(message)s')

class Namespace:
    def __init__(self, conf, ns_name):
        self.conf = conf
        self.ns_name = ns_name

        if conf.local_only:
            self._init_local()
        else:
            self._init_aws()

        self.dev_set = set()
        if self.dev_list is not None:
            for dev_dict in self.dev_list:
                self.dev_set.add(json.loads(dev_dict, cls=DeviceDecoder))

        self.ns_set = set()
        if self.ns_list is not None:
            for ns_dict in self.ns_list:
                self.ns_set.add(json.loads(ns_dict, cls=PeerNSDecoder))

        self._self_sign()

    
    def _self_sign(self):
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 1024)
        try:
            #Create the self signed namespace certficate
            x509 = X509("", k, self.ns_name, "US", "NJ", "Princeton")
            x509.forge_certificate(True)
            x509.sign_certificate(None)
            x509.update_keychain(self.conf, self.ns_name)
        except X509Error as e:
            print str(e)


    def _init_aws(self):
        aws_conf = self.conf.aws_conf
        self.dynamo = boto.connect_dynamodb(aws_conf.access_key, aws_conf.secret_key)     
        self.iam = boto.connect_iam(aws_conf.access_key, aws_conf.secret_key)
        
        response = self.iam.get_user()
        user = response['get_user_response']['get_user_result']['user']
        self.id = user['user_id']

        namespace_table = self.dynamo.get_table('namespaces')
        namespace = namespace_table.get_item(self.id)

        self.ns_list = namespace['ns_list']
        self.dev_list = namespace['dev_list']

    def _init_local(self):
        self.devl_fd = open(self.conf.dev_list_path, "a+")
        self.nsl_fd = open(self.conf.ns_list_path, "a+")
        self.dev_list = None
        self.ns_list = None
        #Parse the device list and pack them in a set
        try:
            self.dev_list = json.load(self.devl_fd)
            
        except ValueError as e:
            logging.warning("%s:%s",self.conf.dev_list_path, str(e))

        #Parse the namespace list and pack them in a set
        try:
            self.ns_list = json.load(self.nsl_fd)

        except ValueError as e:
            logging.warning("%s:%s", self.conf.ns_list_path, str(e))

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
        x509 = X509.load_certificate_from_keychain(self.conf, self.ns_name)
        cert_key = x509.get_certificate()
        cert = cert_key[0]
        key  = cert_key[1]
        dev_x509 = X509.load_certifacate_from_PEM(ucert_pem)
        dev_x509.sign_certificate(cert, key)
        dev.cert_pem = dev_x509.get_PEM_certificate()[0]
        self._add_device(dev)
        #write the signed certificate dev.cert_pem back to connection 

    def _remove_device(self, device):
        self.dev_set.remove(device)

    def _add_peer_namespace(self, pns):
        self.ns_set.add(pns)

    def _remove_peer_namespace(self, pns):
        self.ns_set.remove(pns)


def main():
    conf = Configuration(local_only=True)
    from OpenSSL import crypto
    with Namespace(conf, "wathsala") as ns:
        dev0 = Device(10, "iPhone", None, conf=conf)
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 1024)
        dev0.join_namespace("wathsala")
        ns.add_device(dev0)
        ns.sync_local_storage()

if __name__ == "__main__":
    main()

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

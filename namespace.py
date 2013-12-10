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
import copy

from configuration import Configuration

from boto import dynamodb2, iam
from boto.dynamodb2.items import Item
from boto.dynamodb2.table import Table
from boto.dynamodb2.exceptions import DynamoDBError
from boto.dynamodb.exceptions import DynamoDBKeyNotFoundError

from safe_list import SafeList
from device import Device
from peer_ns import PeerNS
from X509 import X509, X509Error
from OpenSSL import crypto

#Setup logging...
logging.basicConfig(format='%(levelname)s:%(message)s')

def transaction(f):
    def wrapped(*args, **kwargs):
        self = args[0]
        if self.conf.local_only:
            return f(*args, **kwargs)

        committed = False
        retries_left = num_retries = 5
        while not committed and retries_left:
            retries_left -= 1
            f(*args, **kwargs)
            new = self.serialize()
            for key, value in new.items():
                if self.serialized.get(key) and self.serialized.get(key) != value:
                    self.serialized[key] = value
            if self.serialized.save():
                committed = True
            else:
                self._reconcile_state()
        if not committed:
            # TODO: better excpetion
            raise Exception("Failed to commit change after %d attempts" % (num_retries,)) 
    return wrapped

class Namespace(object):    
    def __init__(self, conf, ns_name=None):
        self.conf = conf
        self.ns_name = ns_name

        if conf.local_only:
            self._init_local()
        else:
            self._init_aws()

        self._reconcile_state()
        self._self_sign() 

    def serialize(self):
        """ returns a dictionary representing the serialization of the state of the namespace """
        return {
            'ns_list': self.ns_list.serialize(),
            'dev_list': self.dev_list.serialize(),
            'metadata': json.dumps(self.metadata),
        }

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

    def _reconcile_state(self):
        if self.conf.local_only:
            return
        namespace_table = self.dynamo.get_table('namespaces')
        try:
            self.serialized = namespace_table.get_item(self.id)
        except DynamoDBKeyNotFoundError as e:
            self.ns_list = SafeList("", cls=PeerNS)
            self.dev_list = SafeList("", cls=Device)
            serialized = {
                    'user_id': self.id,
                    'ns_list': self.ns_list.serialize(), 
                    'dev_list': self.dev_list.serialize(), 
                    'metadata': '{}'}
            self.serialized = Item(namespace_table, data=serialized)
            self.serialized.save()
            return

        if hasattr(self, 'ns_list'):
            self.ns_list.update_from_serialization(self.serialized['ns_list'])
        else:    
            self.ns_list = SafeList(self.serialized['ns_list'], PeerNS)

        if hasattr(self, 'dev_list'):
            self.dev_list.update_from_serialization(self.serialized['dev_list'])
        else:
            self.dev_list = SafeList(self.serialized['dev_list'], Device)

        self.metadata = json.loads(self.serialized['metadata'])

    def _init_local(self):
        self.devl_fd = open(self.conf.dev_list_path, "a+")
        self.nsl_fd = open(self.conf.ns_list_path, "a+")
        self.dev_list = None
        self.ns_list = None
        #Parse the device list and pack them in a set
        try:
            self.dev_list = SafeList(self.devl_fd.read(), cls=Device)
            
        except ValueError as e:
            logging.warning("%s:%s",self.conf.dev_list_path, str(e))
            self.dev_list = SafeList("", cls=Device)

        #Parse the namespace list and pack them in a set
        try:
            self.ns_list = SafeList(self.nsl_fd.read(), cls=PeerNS)

        except ValueError as e:
            logging.warning("%s:%s", self.conf.ns_list_path, str(e))
            self.ns_list = SafeList("", cls=PeerNS)

        self.serialized = {'ns_list': self.ns_list, 'dev_list': self.dev_list}

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        if self.conf.local_only:
            self.sync_local_storage()
            self.devl_fd.close()
            self.nsl_fd.close()
    
    def get_device_list(self):
        return json.dumps(list(self.dev_set), cls=Device.ENCODER)
    
    def get_peer_ns_list(self):
        return json.dumps(list(self.ns_set), cls=PeerNS.ENCODER)

    def sync_local_storage(self):
        if self.conf.local_only:
            self.devl_fd.truncate(0)
            dev_list_json = self.dev_list.serialize()
            self.devl_fd.write(dev_list_json)
            self.nsl_fd.truncate(0)
            ns_list_json = self.ns_list.serialize()
            self.nsl_fd.write(ns_list_json)

    @transaction
    def _add_device(self, device):
        self.dev_list.add(device)

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

    @transaction
    def _remove_device(self, device):
        self.dev_set.remove(device)

    @transaction
    def _add_peer_namespace(self, pns):
        self.ns_set.add(pns)
        # allow the peer namespace to access the metadata

    @transaction
    def _remove_peer_namespace(self, pns):
        self.ns_set.remove(pns)
        # disallow the peer namespace from accessing the metadata

def main():
    conf = Configuration(".safe_config")

    from OpenSSL import crypto
    with Namespace(conf, "foo") as ns:
        dev0 = Device(10, "iPhone", None, conf=conf)
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 1024)
        dev0.join_namespace("wathsala")
        ns.add_device(dev0)
        #ns.sync_local_storage()

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

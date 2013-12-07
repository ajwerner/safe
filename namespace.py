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

from device import Device
from device import DeviceEncoder
from device import DeviceDecoder
from device import DeviceError

from peer_ns import PeerNS
from peer_ns import PeerNSEncoder
from peer_ns import PeerNSDecoder
from peer_ns import PeerNSError

class Namespace:
    def __init__(self, conf):
        self.conf = conf

        if conf.local_only:
            self._init_local()
        else:
            self._init_aws()

        self.dev_set = set()
        for dev_dict in self.dev_list:
            self.dev_set.add(json.loads(dev_dict, cls=DeviceDecoder))

        self.ns_set = set()
        for ns_dict in self.ns_list:
            self.ns_set.add(json.loads(ns_dict, cls=PeerNSDecoder))

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

    def _remove_device(self, device):
        self.dev_set.remove(device)

    def _add_peer_namespace(self, pns):
        self.ns_set.add(pns)

    def _remove_peer_namespace(self, pns):
        self.ns_set.remove(pns)

def main():
    conf = Configuration()
    ns = Namespace(conf)

if __name__ == "__main__":
    main()

'''Test Namespace
with Namespace("/tmp/dev_list", "/tmp/ns_list") as ns:
    dev0 = Device(10, "iPhone", None)
    dev1 = Device(11, "iPad", None)
    dev2 = Device(12, "MacBook", None)
    ns.add_device(dev0)
    ns.add_device(dev1)
    ns.add_device(dev2)
    ns.remove_device(dev1)

    pns0 = PeerNS(1000, "Bob", "AAAAAAAAAAAAAAAAAAA")
    pns1 = PeerNS(1001, "Dac", "AAAAACCCCAAAAAAAAAA")
    pns2 = PeerNS(1002, "Carla", "AAAAAAFFFFFFFFFFFF")
    ns.add_peer_namespace(pns0)
    ns.add_peer_namespace(pns1)
    ns.add_peer_namespace(pns2)
    ns.remove_peer_namespace(pns1) 
    print ns.get_device_list()
    print ns.get_peer_ns_list()

    ns.sync_local_storage()
'''

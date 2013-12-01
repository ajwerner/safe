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

#Setup logging...
logging.basicConfig(format='%(levelname)s:%(message)s')

class Namespace:
    def __init__(self, dev_list, ns_list):
        self.dev_list = dev_list
        self.ns_list = ns_list
        try:
            self.devl_fd = open(self.dev_list)
        except IOError as e:
            self.devl_fd = open(self.dev_list, "w+")

        try:
            self.nsl_fd = open(self.ns_list)
        except IOError as e:
            self.nsl_fd = open(self.ns_list, "w+")

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


        self.devl_fd.close()
        self.nsl_fd.close()

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.devl_fd = open(self.dev_list, "w+")
        self.devl_fd.truncate(0)
        json.dump(list(self.dev_set), self.devl_fd, cls=DeviceEncoder)
        self.devl_fd.close()

        self.nsl_fd = open(self.ns_list, "w+")
        self.nsl_fd.truncate(0)
        json.dump(list(self.ns_set), self.nsl_fd, cls=PeerNSEncoder)
        self.nsl_fd.close()

    def add_device(self, device):
        self.dev_set.add(device)

    def remove_device(self, device):
        self.dev_set.remove(device)

    def add_peer_namespace(self, pns):
        self.ns_set.add(pns)

    def remove_peer_namespace(self, pns):
        self.ns_set.remove(pns)

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
''' 

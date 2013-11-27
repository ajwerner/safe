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
from device import DeviceError

#Setup logging...
logging.basicConfig(format='%(levelname)s:%(message)s')

class Namespace:
    def __init__(self, dev_list, ns_list):
        self.dev_list = dev_list
        self.ns_list = ns_list
        self.devl_fd = open(self.dev_list, "w+b")
        self.nsl_fd = open(self.dev_list, "w+b")
        self.dev_list_obj = None
        self.ns_list_obj = None
        #Parse the device list and decode
        try:
            self.dev_list_obj = json.load(self.devl_fd)
        except ValueError as e:
            logging.warning("%s:%s",self.dev_list, str(e))
            #Write the list container in JSON format
            self.dev_list_obj = list()
        try:
            self.ns_list_obj = json.load(self.nsl_fd)
        except ValueError as e:
            logging.warning("%s:%s",self.ns_list, str(e))
            #Write the list container in JSON format
            self.ns_list_obj = list()
            #print json.dumps(ns_list, cls=NamespaceEncoder)

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.devl_fd.truncate(0)
        json.dump(self.dev_list_obj, self.devl_fd, cls=DeviceEncoder)
        self.devl_fd.close()
        self.nsl_fd.close()

    def add_device(self, device):
        self.dev_list_obj.append(device)

'''Test Namespace
with Namespace("/tmp/dev_list", "/tmp/ns_list") as ns:
    dev = Device(10, "iPhone", None)
    ns.add_device(dev)
    dev = Device(1, "laptop", None)
    ns.add_device(dev)
'''

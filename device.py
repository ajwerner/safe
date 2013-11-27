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
        if dec_str is not None:
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
    print dev
    json_dev = json.dumps(dev, cls=DeviceEncoder)
    #print json_dev
    dev2 = json.loads(json_dev, cls=DeviceDecoder)
    print dev2
except DeviceError as e:
    print "Error"
'''

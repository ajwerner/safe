# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4

"""safe_list.py: a module to store, encode, encrypt, and verify lists for the namespace state"""
__author__      = "Andrew Werner"
__email__       = "ajwerner@princeton.edu"
__copyright__   = "Copyright 2013, Safe Project"
__credits__     = ["Wathsala Vithanage", "Stephen Lin"]
__license__     = "Apache"
__version__     = "0.1"

import json

class SafeList(object):
    def __init__(self, serialization, cls):
        self.cls = cls
        self.encoder = cls.ENCODER
        self.decoder = cls.DECODER
        self.set = set()
        
        if not serialization:
            return

        self.update_from_serialization(serialization)

    def serialize(self):
        return json.dumps(list(self.set), cls=self.encoder)

    def update_from_serialization(self, serialization):
        """ in place deserialization for the PeerNSList object """
        if not serialization:
            raise ValueError("NoneType serialization given")

        new_set = set()
        obj_dict_list = json.loads(serialization)
        if not obj_dict_list:
            return
        for obj_str in obj_dict_list:
            if not obj_str:
                continue
            obj = json.loads(obj_str, cls=self.decoder)
            new_set.add(obj)
        self.set = new_set

    def add(self, obj):
        if not isinstance(obj, self.cls):
            raise TypeError("object passed is of wrong type")
        self.set.add(obj)

    def __repr__(self):
        return self.serialize()
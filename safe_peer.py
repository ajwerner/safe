# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4

"""peer_ns.py: A Simple implementation of a peer namespace for Safe."""

__author__      = "Wathsala Vithanage"
__email__       = "wathsala@princeton.edu"
__copyright__   = "Copyright 2013, Safe Project"
__credits__     = ["Andrew Werner", "Stephen Lin"]
__license__     = "Apache"
__version__     = "0.1"

"""
A peer namespace is a namespace owned by a different entity in the network. 
For instance Alice the owner of the namespace alice can have N number of peer namespaces which she is connected to but owned by Bob, Carla, Dan, ... etc. 
"""
import time
import json

class SafePeerError():
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return str(self.value)

class SafePeerEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, SafePeer):
            return obj.__dict__
        else:
            return json.JSONEncoder.default(self, obj)

class SafePeerDecoder(json.JSONDecoder):
    def decode(self, json_str):
        try:
            dec_dict = json.loads(str(json_str))
        except ValueError as e:
            raise e
        if dec_dict is not None:
            return SafePeer(**dec_dict)
        else:
            return None

class SafePeer:
    ENCODER = SafePeerEncoder
    DECODER = SafePeerDecoder

    def __init__(self, id=None, user_name=None, cert_pem=None, ctime=-1, remote_index=None, local_index=None):
        self.remote_index = remote_index
        self.local_index = local_index
        self.id = id
        self.user_name = user_name
        self.cert_pem = cert_pem
        if ctime > -1:
            self.ctime = ctime
        else:
            self.ctime = time.time()

    def __repr__(self):
        return str(self)

    def __str__(self):
        return "%s#%s" % (self.user_name, self.id)

    def __hash__(self):
        return hash(self.id)

    def __cmp__(self, other):
        return cmp(self.id, other.id)

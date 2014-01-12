# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4

"""peer_ns.py: A Simple implementation of a peer namespace for Safe."""

__author__      = "Wathsala Vithanage"
__email__       = "wathsala@princeton.edu"
__copyright__   = "Copyright 2013, Safe Project"
__credits__     = ["Andrew Werner", "Stephen Lin"]
__license__     = "Apache"
__version__     = "0.1"

"""
A peer namespace is a namespace owned by a different entity in the network. For instance Alice the owner of the namespace alice can have N number of peer namespaces which she is connected to but owned by Bob, Carla, Dan, ... etc. 

Peer namespaces are stored in the disk in following JSON format.

    {
        "ns_id":        "A unique 128-bit ID"
        "ns_name":      "ALice"
        "ctime":        "10/11/2013"
        "pub_key":      "PEM encoded RSA public key"
    }
"""
import time
import json

class PeerNSError():
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return str(self.value)

class PeerNSEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, PeerNS):
            return obj.__dict__
        else:
            return json.JSONEncoder.default(self, obj)

class PeerNSDecoder(json.JSONDecoder):
    def decode(self, json_str):
        try:
            dec_dict = json.loads(str(json_str))
        except ValueError as e:
            raise e
        if dec_dict is not None:
            return PeerNS(**dec_dict)
        else:
            return None

class PeerNS:
    ENCODER = PeerNSEncoder
    DECODER = PeerNSDecoder

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

'''Test PeerNS class
try:
    pns = PeerNS("1904A579", "Alice", "AAAAAAAAAAAAAAAAA")
    print pns
    json_pns = json.dumps(pns, cls=PeerNSEncoder)
    print json_pns
    pns2 = json.loads(json_pns, cls=PeerNSDecoder)
    print pns2
except PeerNSError as e:
    print "Error"
'''

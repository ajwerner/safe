from namespace import Namespace
from peer_ns import PeerNS
from tofu import *
from configuration import Configuration

conf = Configuration(local_only = True)
ns = Namespace(conf)
print ns.__dict__
tc = tofu(input_callback)
ns.join_peer_namespace(tc)


from namespace import Namespace
from peer_ns import PeerNS
from tofu import *
from configuration import Configuration
import sys, getopt

def ns_controller_join_ns(ns):
    #print ns.__dict__
    tc = tofu(input_callback)
    ns.join_peer_namespace(tc)

def ns_controller_add_ns(ns):
    tc = tofu(input_callback)
    ns.add_peer_namespace(tc)

def main(argv):
    conf = Configuration()
    ns = Namespace(conf)
    try:
        opts, args = getopt.getopt(argv,"haj",["add-ns","join-ns"])
    except getopt.GetoptError as e:
        print e
        print 'namesapce_controller.py -h for more information'
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print '-a, --add-ns Adds a Namespace in to PeerNS list.'
            print '-j, --join-ns Joins this Namespace with another.'
            sys.exit()
        elif opt in ("-a", "--add-ns"):
            ns_controller_add_ns(ns)
            sys.exit()
        elif opt in ("-j", "--join-ns"):
            ns_controller_join_ns(ns)
            sys.exit()

if __name__ == "__main__":
    main(sys.argv[1:])


from safe_user import SafeUser
from peer_ns import SafePeer
import sys, getopt

def main(argv):
    ns = SafeUser()
    try:
        opts, args = getopt.getopt(argv,"ha",["add-ns"])
    except getopt.GetoptError as e:
        print e
        print 'namesapce_controller.py -h for more information'
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print '-a, --add-ns Adds a Namespace in to SafePeer list.'
            sys.exit()
        elif opt in ("-a", "--add-ns"):
            ns.add_peer()
            sys.exit()

if __name__ == "__main__":
    main(sys.argv[1:])


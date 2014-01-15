from safe_device import SafeDevice
from tofu import *
from configuration import Configuration
from safe_user import SafeUser
import sys, getopt

def main(argv):
    try:
        opts, args = getopt.getopt(argv,"hj",["join-ns"])
    except getopt.GetoptError as e:
        print e
        print 'device_controller.py -h for more information'
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print '-j, --join-ns Joins a device with another.'
            sys.exit()
        elif opt in ("-j", "--join-ns"):
            ns = SafeUser()
            ns.add_device()
            sys.exit()

if __name__ == "__main__":
    main(sys.argv[1:])

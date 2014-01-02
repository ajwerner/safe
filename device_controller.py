from device import Device
from tofu import *
from configuration import Configuration
from namespace import Namespace
import sys, getopt

def dev_controller_join_ns():
    conf = Configuration("%s" % raw_input("Device Configuration Dir: "))
    try:
        ns = Namespace(conf)
    except Exception as e:
        print e
    tc = tofu(input_callback)
    ns = Namespace.join(conf, tc)
    return ns

def dev_controller_add_dev(ns):
    tc = tofu(input_callback)
    ns.add_device(tc)

def main(argv):
    try:
        opts, args = getopt.getopt(argv,"haj",["add-dev","join-ns"])
    except getopt.GetoptError as e:
        print e
        print 'device_controller.py -h for more information'
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print '-a, --add-dev Adds a device in to Namespace.'
            print '-j, --join-ns Joins a device with another.'
            sys.exit()
        elif opt in ("-a", "--add-dev"):
            conf = Configuration()
            ns = Namespace(conf)
            dev_controller_add_dev(ns)
            sys.exit()
        elif opt in ("-j", "--join-ns"):
            dev_controller_join_ns()
            sys.exit()

if __name__ == "__main__":
    main(sys.argv[1:])

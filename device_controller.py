from device import Device
from tofu import *
from configuration import Configuration
from namespace import Namespace

conf = Configuration("%s" % raw_input("Device Configuration Dir: "))
try:
	ns = Namespace(conf)
except Exception as e:
	print e
tc = tofu(input_callback)
ns = Namespace.join(conf, tc)
print ns

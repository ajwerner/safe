from device import Device
from tofu import *
from configuration import Configuration

conf = Configuration(".safe_config")
dev = Device(10, "iPhone", None, conf=conf)
tc = tofu(input_callback)
dev.join_namespace("foo", tc)

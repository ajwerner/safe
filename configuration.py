# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4

"""configuration.py: a module to interface with the safe library configuration"""
__author__      = "Andrew Werner"
__email__       = "ajwerner@princeton.edu"
__copyright__   = "Copyright 2013, Safe Project"
__credits__     = ["Wathsala Vithanage", "Stephen Lin"]
__license__     = "Apache"
__version__     = "0.1"

import sys
import json
import logging
import boto
from os import path
from boto import dynamodb2, iam

# Default paths in configuration dir

AWS_CONF_PATH   = 'aws.json'
DEV_LIST_PATH   = 'dev_list.json'
NS_LIST_PATH    = 'ns_list.json'
DEV_CONF        = 'dev.cfg'

AWS_ACCESS_KEY = 'aws_access_key_id'
AWS_SECRET_KEY = 'aws_secret_key_id'


class Configuration(object):
    def __init__(self, config_dir=".safe_config", local_only=False):
        self.local_only = local_only
        config_dir = path.abspath(config_dir)

        # init conf
        self.ns_list_path = path.join(config_dir, NS_LIST_PATH)
        self.dev_list_path = path.join(config_dir, DEV_LIST_PATH)
        self.dev_conf = path.join(config_dir, DEV_CONF)
        self.config_dir = config_dir

        # init aws_conf
        aws_config_path = path.join(config_dir, AWS_CONF_PATH)
        self.aws_conf = AWSConf(aws_config_path)

class AWSConf(object):
    REGION = 'us-east-1'

    def __init__(self, conf_path):
        conf_file = open(conf_path, 'ro')
        conf_dict = json.load(conf_file)
        self.secret_key = str(conf_dict[AWS_SECRET_KEY])
        self.access_key = str(conf_dict[AWS_ACCESS_KEY])

    @classmethod
    def create(cls, conf_file_path, access_key, secret_key):
        with open(conf_file_path, 'a+') as conf_file:
            json_string = json.dumps({AWS_ACCESS_KEY: access_key, AWS_SECRET_KEY: secret_key})
            conf_file.write(json_string)

    def __repr__(self):
        return "{AWS Access Key: %s, AWS Secret Key: %s}" % (self.access_key, self.secret_key)


def main():
    """ test client """
    conf = Configuration(".safe")
    aws_conf = conf.aws_conf
    dynamo = boto.dynamodb2.connect(aws_conf.access_key, aws_conf.secret_key)
    iam = iam.connect_to_region(aws_conf.REGION, 
                                         aws_access_key_id=aws_conf.access_key, 
                                         aws_secret_key_id=aws_conf.secret_key)
            

if __name__ == "__main__":
    main()

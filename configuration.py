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
import getpass
import os
import random
from OpenSSL        import crypto, SSL
from X509 import X509, X509Error
from keychain import KeyChain
from os import path, makedirs
from boto import dynamodb2, iam

# Default paths in configuration dir

CONF_PATH       = 'config.json'
DEV_LIST_PATH   = 'dev_list.json'
NS_LIST_PATH    = 'ns_list.json'
KEYCAIN_PATH    = 'device_keychain.kc'

AWS_USERNAME = 'aws_username'
AWS_ACCESS_KEY = 'aws_access_key_id'
AWS_SECRET_KEY = 'aws_secret_key_id'

def create_config(conf_path):
    dev_info = {
        'dev_name': raw_input("Device Name:").strip(),
        'dev_id': random.randint(0, 65535)
    }
    user_info = {
            'country': raw_input("Country: ").strip(),
            'state': raw_input("State: ").strip(),
            'city': raw_input("City: ").strip()
    }
    aws_info = {
            AWS_USERNAME: raw_input("AWS Username: ").strip(),
            AWS_ACCESS_KEY: raw_input("AWS Access Key: ").strip(),
            AWS_SECRET_KEY: raw_input("AWS Secret Key: ").strip()
    }
    conf = {
        'dev_conf': dev_info,
        'user_conf': user_info,
        'aws_conf': aws_info
    }
    with open(conf_path, 'w') as aws_conf_file:
        json_string = json.dumps(conf)
        aws_conf_file.write(json_string) 

def create_keychain(keychain_path, conf):
        print "Enter information for device certificate"
        kc_passwd = getpass.getpass("Device Keychain Password: ")

        pkey = crypto.PKey()
        pkey.generate_key(crypto.TYPE_RSA, 1024)
        x509 = X509(conf['dev_conf']['dev_name'], pkey, 
                    conf['aws_conf'][AWS_USERNAME],
                    conf['user_conf']['country'], 
                    conf['user_conf']['state'], 
                    conf['user_conf']['city'])
        x509.forge_certificate(False)
        x509.sign_certificate(None)
        rec = x509.get_PEM_certificate()
        cert_pem = rec[0]
        key_pem  = rec[1]

        kc = KeyChain(keychain_path, conf['dev_conf']['dev_name'], kc_passwd)
        if kc.write_keychain(cert_pem, key_pem) < 0:
            raise X509Error("Certificate exists: "+keychain_name)

class Configuration(object):
    REGION = 'us-east-1'

    def __init__(self, config_dir="~/.safe_config", local_only=False):
        self.local_only = local_only
        self.config_dir = path.abspath(config_dir)
        if not path.exists(config_dir):
            os.makedirs(self.config_dir)

        # init conf for local_only
        if local_only:
            self.ns_list_path = path.join(self.config_dir, NS_LIST_PATH)
            self.dev_list_path = path.join(self.config_dir, DEV_LIST_PATH)

        config_path = path.join(config_dir, CONF_PATH)
        if not path.exists(config_path):
            create_config(config_path)
        with open(config_path, 'ro') as config_file:
            self.conf = json.load(config_file)

        self.dev_conf = self.conf['dev_conf']
        self.aws_conf = self.conf['aws_conf']
        self.user_conf = self.conf['user_conf']

        # init 
        keychain_path = path.join(config_dir, KEYCAIN_PATH)
        if not path.exists(keychain_path):
            create_keychain(keychain_path, self.conf)
        self.dev_keychain = KeyChain(keychain_path, self.dev_conf['dev_name'], getpass.getpass("Device Keychain Password: "))


def main():
    """ test client """
    conf = Configuration(".safe")

if __name__ == "__main__":
    main()

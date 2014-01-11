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
from safe_device     import SafeDevice
from OpenSSL    import crypto, SSL
from X509       import X509, X509Error
from keychain   import KeyChain
from os         import path, makedirs
from boto       import dynamodb2, iam

REGION = 'us-east-1'

# Default paths in configuration dir
CONF_PATH       = 'conf.json'
DEV_LIST_PATH   = 'dev_list.json'
NS_LIST_PATH    = 'ns_list.json'
KC_PATH         = 'device_keychain.kc'

AWS_USERNAME = 'aws_username'
AWS_ACCESS_KEY = 'aws_access_key_id'
AWS_SECRET_KEY = 'aws_secret_key_id'

def join_namespace(config_dir):
    """ initiates a tofu connection with another device for this user,
        gets the AWS and namespace configuration information, 
        writes that to disk
    """
    # tofu <- make tofu to another device (using the SafeUser.add_device() )
    # conf <- receive configuration from tofu
    # set up the device
    #    get a name / device id
    #    make a certificate
    #    write the keychain
    #    send the certificate back over the tofu
    # return conf

def initialize_new_conf(conf):
    """ creates a new configuration file from prompting a user for the fields"""
    # set up dictionaries
    dev_info = {
        'dev_name': raw_input("Device Name: ").strip(),
        'dev_id': random.randint(0, 65535)
    }
    user_info = {
            'country': raw_input("Country: ").strip(),
            'state': raw_input("State: ").strip(),
            'city': raw_input("City: ").strip() }
    aws_info = {
            AWS_USERNAME: raw_input("AWS Username: ").strip(),
            AWS_ACCESS_KEY: raw_input("AWS Access Key: ").strip(),
            AWS_SECRET_KEY: raw_input("AWS Secret Key: ").strip()
    }
    conf.update({
        'dev_conf': dev_info,
        'user_conf': user_info,
        'aws_conf': aws_info
    })

    cert_pem, privkey_pem = create_device_certificates(conf)
    conf['dev_conf']['cert_pem'] = cert_pem
    with open(conf['conf_path'], 'w') as conf_file:
        json_string = json.dumps(conf)
        conf_file.write(json_string)

    # Make the keychain
    kc_password = getpass.getpass("Enter a password for this device's Keychain: ")
    kc = KeyChain(conf['kc_path'], conf['dev_conf']['dev_name'], kc_password)
    kc.write_keychain(cert_pem, privkey_pem)
    conf['dev_keychain'] = kc

def load_existing_conf(conf):
    """ loads an existing configuration from the configuration path"""
    # load the configuration from json
    with open(conf['conf_path'], "r") as config_file:
        conf.update(json.load(config_file))
    kc_password = getpass.getpass("Enter a password for this device's Keychain: ")
    kc = KeyChain(conf['kc_path'], conf['dev_conf']['dev_name'], kc_password)
    conf['dev_conf']['cert_pem'] = kc.read_keychain()[0]
    conf['dev_keychain'] = kc
    return conf


def create_device_certificates(conf, signer = None):
    """ 
    creates a X509 certificate/private key pair 
    
    returns: (cert_pem, privkey_pem)
    """
    pkey = crypto.PKey()
    pkey.generate_key(crypto.TYPE_RSA, 1024)
    x509 = X509(conf['dev_conf']['dev_id'], pkey, 
                conf['aws_conf'][AWS_USERNAME], conf['user_conf']['country'], 
                conf['user_conf']['state'], conf['user_conf']['city'])
    x509.forge_certificate(False)
    x509.sign_certificate(signer)
    rec = x509.get_PEM_certificate()
    cert_pem = rec[0]
    key_pem  = rec[1]
    return (cert_pem, key_pem)

def get_config(conf_dir):
    conf = {}
    conf_dir = path.abspath(conf_dir)
    if not path.exists(conf_dir):
        os.makedirs(conf_dir)

    conf['conf_path'] = path.join(conf_dir, CONF_PATH)
    conf['kc_path'] = path.join(conf_dir, KC_PATH)
    if path.exists(conf['conf_path']):
        load_existing_conf(conf)    
        if not conf or not conf_is_valid(conf):
            print "Invalid configuration found at %s" % conf['conf_path']
    else:
        print "No existing configuration found at %s" % conf['conf_path']
    
    response = None;
    while not conf.get('dev_keychain'):
        # prompt the user for a type of setup correctly
        if not response:
            response = raw_input("Is this the first device on which you've configured Safe? (y/n)")
        else:
            response = raw_input("Please enter 'y' or 'n': ")
        # do the right type of configuration setup
        response_char = response.strip().lower()[0]
        if   (response_char == 'y'):
            initialize_new_conf(conf)
            break
        elif (response_char == 'n'):
            conf = join_namespace(conf)
            break
    # init 
    conf['dev'] = SafeDevice(**conf['dev_conf'])
    return conf

def conf_is_valid(conf_dict):
    """ Validates the configuration"""
    # TODO: this
    return True
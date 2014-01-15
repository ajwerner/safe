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
from uuid           import uuid4
from base64         import urlsafe_b64encode
from tofu           import tofu
from safe_device    import SafeDevice
from OpenSSL        import crypto, SSL
from X509           import X509, X509Error
from keychain       import KeyChain
from os             import path, makedirs
from boto           import dynamodb2, iam

# Some Amazon Constants
S3_BASE_URL = "http://s3.amazonaws.com"
S3_DROPBOX_BUCKET = 'safe-dropbox'
REGION = 'us-east-1'

# Default paths in configuration dir
CONF_PATH       = 'conf.json'
DEV_LIST_PATH   = 'dev_list.json'
NS_LIST_PATH    = 'ns_list.json'
LOG_PATH        = 'log.json'
KC_PATH         = 'device_keychain.kc'

# Configuration keys
AWS_USERNAME   = 'aws_username'
AWS_ACCESS_KEY = 'aws_access_key_id'
AWS_SECRET_KEY = 'aws_secret_key_id'
AWS_CONF_KEYS = (AWS_USERNAME, AWS_ACCESS_KEY, AWS_SECRET_KEY)

CERT_PEM = 'cert_pem'
DEV_NAME = 'dev_name'
DEV_ID = 'dev_id'
DEV_CONF_KEYS = (CERT_PEM, DEV_NAME, DEV_ID)

USER_CONF_KEYS = ['name', 'country', 'state', 'city', 'email']

def join_namespace(conf):
    """ initiates a tofu connection with another device for this user,
        gets the AWS and namespace configuration information, 
        writes that to disk
    """
    tofu_id = raw_input("Enter a code for this connection: ")
    jabber_id = raw_input("Please enter you gmail username: ")
    jabber_pw = getpass.getpass("Please enter your password: ")
    t = tofu(jabber_id, jabber_pw, jabber_id, tofu_id)

    conf['aws_conf'] = json.loads(t.receive())
    conf['user_conf'] = json.loads(t.receive())

    conf['dev_conf'] = {
        'dev_name': raw_input("Device Name: ").strip(),
        'dev_id': urlsafe_b64encode(uuid4().bytes),
    }
    cert_pem, privkey_pem = create_device_certificates(conf)
    conf['dev_conf']['cert_pem'] = cert_pem
    
    # Make the keychain
    dev = SafeDevice(**conf['dev_conf'])
    dev_json = json.dumps(dev, cls=SafeDevice.ENCODER)
    t.send(dev_json)

    signed_cert_pem = t.receive()
    conf['dev_conf']['cert_pem'] = signed_cert_pem

    with open(conf['conf_path'], 'w') as conf_file:
        json_string = json.dumps(conf)
        conf_file.write(json_string)

    kc_password = getpass.getpass("Enter a password for this device's Keychain: ")
    kc = KeyChain(conf['kc_path'], conf['dev_conf']['dev_name'], kc_password)
    kc.write_keychain(conf['dev_conf']['cert_pem'], privkey_pem)
    dev = SafeDevice(**conf['dev_conf'])
    return dev, kc

def initialize_new_conf(conf):
    """ creates a new configuration file from prompting a user for the fields"""
    # get some info
    conf['user_conf'] = {
        'name': raw_input("Name: ").strip(),
        'country': raw_input("Country: ").strip()[:2],
        'state': raw_input("State: ").strip()[:2],
        'city': raw_input("City: ").strip(),
        'email': raw_input("Email Address: ").strip(),
    }
    conf['dev_conf'] = {
        'dev_name': raw_input("Device Name: ").strip(),
        'dev_id': urlsafe_b64encode(uuid4().bytes)
    }

    if not conf.get('aws_conf'):
        conf['aws_conf'] = {
            AWS_USERNAME: raw_input("AWS Username: ").strip(),
            AWS_ACCESS_KEY: raw_input("AWS Access Key: ").strip(),
            AWS_SECRET_KEY: raw_input("AWS Secret Key: ").strip(),
        }

    cert_pem, privkey_pem = create_device_certificates(conf)
    conf['dev_conf']['cert_pem'] = cert_pem

    # write the conf
    with open(conf['conf_path'], 'w') as conf_file:
        json_string = json.dumps(conf)
        conf_file.write(json_string)

    kc_password = getpass.getpass("Enter a password for this device's Keychain: ")
    kc = KeyChain(conf['kc_path'], conf['dev_conf']['dev_name'], kc_password)
    kc.write_keychain(conf['dev_conf']['cert_pem'], privkey_pem)

    dev = SafeDevice(**conf['dev_conf'])
    return dev, kc

def load_existing_conf(conf):
    """ loads an existing configuration from the configuration path"""
    # load the configuration from json
    with open(conf['conf_path'], "r") as config_file:
        conf.update(json.load(config_file))
    kc_password = getpass.getpass("Enter a password for this device's Keychain: ")
    kc = KeyChain(conf['kc_path'], conf['dev_conf']['dev_name'], kc_password)
    conf['dev_conf']['cert_pem'] = kc.read_keychain()[0]
    dev = SafeDevice(**conf['dev_conf'])
    return dev, kc

def create_device_certificates(conf, signer = None):
    """ 
    creates a X509 certificate/private key pair 
    
    returns: (cert_pem, privkey_pem)
    """
    pkey = crypto.PKey()
    pkey.generate_key(crypto.TYPE_RSA, 1024)
    x509 = X509(conf['dev_conf']['dev_name'], pkey, 
                conf['user_conf']['name'], conf['user_conf']['country'], 
                conf['user_conf']['state'], conf['user_conf']['city'])
    x509.forge_certificate(False)
    x509.sign_certificate(signer)
    rec = x509.get_PEM_certificate()
    cert_pem = rec[0]
    key_pem  = rec[1]
    return (cert_pem, key_pem)

def get_config(conf_dir, credentials_csv_path=None):
    """
    Assembles the configuration for the SafeUser

    params:
        conf_dir - the name of the directory where you want the configuration files to go 
        credentials_csv_path - a path to a credentials.csv file with amazon info 

    returns: (conf, dev, kc) 
        conf - the SafeUser configuration dictionary (user_conf, aws_conf, dev_conf)
        dev - SafeDevice object that representis this device
        kc - the Keychain for this device
    """
    conf = {}
    if credentials_csv_path:
        try:
            with open(credentials_csv_path, "r") as creds_file:
                username, access_key, secret_key = map(str, creds_file.read().strip().split(','))
                conf['aws_conf'] = {
                    AWS_USERNAME: username,
                    AWS_ACCESS_KEY: access_key,
                    AWS_SECRET_KEY: secret_key
                }
        except:
            logging.error("Invalid Amazon credential file at %s" % credentials_csv_path)

    if not path.exists(conf_dir):
        os.makedirs(conf_dir)

    conf['conf_path'] = path.join(conf_dir, CONF_PATH)
    conf['kc_path'] = path.join(conf_dir, KC_PATH)
    conf['log_path'] = path.join(conf_dir, LOG_PATH)
    dev = None
    kc = None
    if path.exists(conf['conf_path']):
        dev, kc = load_existing_conf(conf)    
        if not conf or not conf_is_valid(conf):
            print "Invalid configuration found at %s" % conf['conf_path']
    else:
        print "No existing configuration found at %s" % conf['conf_path']
    
    response = None;
    while not dev or not kc:
        # prompt the user for a type of setup correctly
        if not response:
            response = raw_input("Is this the first device on which you've configured Safe? (y/n) ")
        else:
            response = raw_input("Please enter 'y' or 'n': ")
        # do the right type of configuration setup
        response_char = response.strip().lower()[0]
        if   (response_char == 'y'):
            dev, kc = initialize_new_conf(conf)
        elif (response_char == 'n'):
            dev, kc = join_namespace(conf)

    return conf, dev, kc

def conf_is_valid(conf):
    """ Validates the configuration"""
    if not all([key in conf['aws_conf'] for key in AWS_CONF_KEYS]):
        return False
    if not all([key in conf['user_conf'] for key in USER_CONF_KEYS]):
        return False
    if not all([key in conf['dev_conf'] for key in DEV_CONF_KEYS]):
        return False
    return True

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4

"""safe_user.py: A Simple namespace implementation for Safe."""
__author__      = "Wathsala Vithanage"
__email__       = "wathsala@princeton.edu"
__copyright__   = "Copyright 2013, Safe Project"
__credits__     = ["Andrew Werner", "Stephen Lin"]
__license__     = "Apache"
__version__     = "0.1"

"""


    Note: All primary storages are cacheable on Amazon S3.
"""

import os
import json
import boto
import logging
import copy
from tofu import *

from configuration import get_config, AWS_USERNAME, AWS_ACCESS_KEY, AWS_SECRET_KEY

from boto import iam
from boto import dynamodb
from boto.dynamodb.exceptions import DynamoDBKeyNotFoundError

from base64 import b64decode, b64encode
from safe_list import SafeList
from safe_device import SafeDevice
from peer_ns import PeerNS
from X509 import X509, X509Error
from keychain import encrypt_with_cert, decrypt_with_privkey, AES_decrypt, AES_encrypt
from OpenSSL import crypto
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto import Random

#Setup logging...
logging.basicConfig(format='%(levelname)s:%(message)s')

NUM_RETRIES = 5 # number of times to retry a transaction

def transaction(f):
    def wrapped(*args, **kwargs):
        self = args[0]
        committed = False
        retries_left = num_retries = NUM_RETRIES
        while not committed and retries_left:
            retries_left -= 1
            f(*args, **kwargs)
            new = self.serialize()
            for key, value in new.items():
                if self.seriaized.get(key) and self.serialized.get(key) != value:
                    self.serialized[key] = value
            committed = self.serialized.save()
            if not committed:
                self._reconcile_state()

        if not committed:
            # TODO: better excpetion
            raise Exception("Failed to commit change after %d attempts" % (num_retries,)) 
    return wrapped

class SafeUser(object):
    def __init__(self, conf_dir=".safe_config"):
        self.conf = get_config(conf_dir)
        self.name = self.conf['aws_conf'][AWS_USERNAME]
        self._init_aws()
        self._reconcile_state()

    @transaction
    def _add_device(self, device):
        self.dev_list.add(device)
        self.keys[device.dev_id] = b64encode(encrypt_with_cert(device.cert_pem, self.state_key))

    def add_device(self, tofu_connection):
        #read the device out from the connection...
        json_dev_str = tofu_connection.receive()
        dev = json.loads(json_dev_str, cls=SafeDevice.DECODER)
        assert isinstance(dev, SafeDevice)

        cert = crypto.load_certificate(crypto.FILETYPE_PEM, self.cert_pem)
        privkey = crypto.load_privatekey(crypto.FILETYPE_PEM, self.privkey_pem)
        dev_x509 = X509.load_certifacate_from_PEM(dev.cert_pem)
        dev_x509.sign_certificate(cert, privkey)
        dev.cert_pem = dev_x509.get_PEM_certificate()[0]
        self._add_device(dev)

        #write the signed certificate dev.cert_pem back to connection
        tofu_connection.send(dev.cert_pem)
        logging.debug("Device Added")

    def serialize(self):
        """ returns a dictionary representing the serialization of the state of the namespace """
        serialization = {
            'privkey_pem': AES_encrypt(self.privkey_pem, self.state_key),
            'cert_pem': AES_encrypt(self.cert_pem, self.state_key),
            'state_keys': json.dumps(self.state_keys),
            'ns_list': AES_encrypt(self.peer_list.serialize(), self.state_key),
            'dev_list': AES_encrypt(self.dev_list.serialize(), self.state_key),
            'metadata_keys': json.dumps(self.metadata_keys),
            'metadata': AES_encrypt(json.dumps(self.metadata), self.metadata_key),
        }
        # serialization['fork_log'] = self.;
        return serialization
        

    def _init_aws(self):
        """
        connects to IAM, dynamodb, and sqs for the user as well as setting the user_id

        may raise on the event of a network error
        """
        aws_conf = self.conf["aws_conf"]
        self.dynamo = boto.connect_dynamodb(aws_conf[AWS_ACCESS_KEY], aws_conf[AWS_SECRET_KEY])
        self.iam = boto.connect_iam(aws_conf[AWS_ACCESS_KEY], aws_conf[AWS_SECRET_KEY])
        response = self.iam.get_user()
        user = response['get_user_response']['get_user_result']['user']
        self.id = user['user_id']

    def _initialize_state(self, namespace_table):
        """ 
        Sets up the user object with the initial values. 
            this function is called when the no database key exists for the user
        """
        # Initial remote serialization creation
        self.peer_list = SafeList("", cls=PeerNS)
        self.dev_list = SafeList("", cls=SafeDevice)
        self.dev_list.add(self.conf['dev'])
        self.state_key = Random.new().read(32)
        # TODO: fix this indexing
        self.state_keys = {self.conf['dev'].dev_id: b64encode(self.conf['dev_keychain'].encrypt(self.state_key))}
        # make a new keypair for the namespace
        pkey = crypto.PKey()
        pkey.generate_key(crypto.TYPE_RSA, 1024)
        x509 = X509(self.id, pkey, 
                self.conf['aws_conf'][AWS_USERNAME],
                self.conf['user_conf']['country'], 
                self.conf['user_conf']['state'], 
                self.conf['user_conf']['city'])
        x509.forge_certificate(False)
        x509.sign_certificate(None)
        rec = x509.get_PEM_certificate()
        self.cert_pem = rec[0]
        self.privkey_pem  = rec[1]
        # set up the metadata
        self.metadata = {'cert_pem': self.cert_pem, 'name': self.name}
        self.metadata_key = Random.new().read(32)
        self.metadata_keys = {self.id: b64encode(encrypt_with_cert(self.cert_pem, self.metadata_key))}
        # create the state object in AWS
        self.serialized = namespace_table.new_item(hash_key=self.id, attrs=self.serialize())
        self.serialized.put()
        # rereconcile because we just changed the remote state
        self._reconcile_state()
        return

    def _reconcile_state(self):
        """
        updates the in-memory representation of the state object to represent the remote serialization.
        called on initialization or any time a conditional write fails.
        """
        namespace_table = self.dynamo.get_table('namespaces')
        try:
            self.serialized = namespace_table.get_item(hash_key=self.id)
        except DynamoDBKeyNotFoundError as e:
            self._initialize_state(namespace_table)
            return

        # Verify log is not forked, then accept log

        # Get the state_key
        self.state_keys = json.loads(self.serialized['state_keys'])
        if str(self.conf['dev'].dev_id) not in self.state_keys:
            raise KeyError("Local device ID not found in keys")
        else:
            state_key = b64decode(self.state_keys[str(self.conf['dev'].dev_id)])
            self.state_key = self.conf['dev_keychain'].decrypt(state_key)

        # Get the namespace keys
        self.cert_pem = AES_decrypt(self.serialized['cert_pem'], self.state_key)
        self.privkey_pem = AES_decrypt(self.serialized['privkey_pem'], self.state_key)

        # Get the peer ns list
        dec_ns_list = AES_decrypt(self.serialized['ns_list'], self.state_key)
        if hasattr(self, 'ns_list'):
            self.peer_list.update_from_serialization(dec_ns_list)
        else:  
            self.peer_list = SafeList(dec_ns_list, PeerNS)

        # Get the device list
        dec_dev_list = AES_decrypt(self.serialized['dev_list'], self.state_key)
        if hasattr(self, 'dev_list'):
            self.dev_list.update_from_serialization(dec_dev_list)
        else:
            self.dev_list = SafeList(dec_dev_list, SafeDevice)

        # get the metadata
        self.metadata_keys = json.loads(self.serialized['metadata_keys'])
        if self.id not in self.metadata_keys:
            raise KeyError("Namespace does not have access to its own metadata!")
        else:
            metadata_key = b64decode(self.metadata_keys[self.id])
            self.metadata_key = decrypt_with_privkey(self.privkey_pem, metadata_key)

        self.metadata = json.loads(AES_decrypt(self.serialized['metadata'], self.metadata_key))

    @classmethod
    def join(cls, conf, tofu):
        dev_json_str = json.dumps(conf['dev'], cls=SafeDevice.ENCODER)
        tofu.send(dev_json_str)
        signed_cert_pem = tofu.receive()
        conf['dev'].cert_pem = signed_cert_pem
        conf['dev_keychain'].update_keychain(signed_cert_pem)
        ns = cls(conf)
        return ns

    def peer(self, connection):
        #read the device out from the connection...
        peer_ns_json = connection.receive()
        peer_ns = json.loads(peer_ns_json, cls=PeerNS.DECODER)
        peer_ns_cert_pem = peer_ns.pub_key
        self._add_peer_namespace(peer_ns)
        ns = self.get_peer_namespace()
        ns_json = json.dumps(ns, cls=PeerNS.ENCODER)
        connection.send(ns_json)

    def join_peer_namespace(self, connection):
        #send a PeerNS instance of this namespace to the 
        #other namespace...
        ns = self.get_peer_namespace()
        ns_json = json.dumps(ns, cls=PeerNS.ENCODER)
        connection.send(ns_json)
        peer_ns_json = connection.receive()
        peer_ns = json.loads(peer_ns_json, cls=PeerNS.DECODER)
        peer_ns_cert_pem = peer_ns.pub_key
        self._add_peer_namespace(peer_ns)

    @transaction
    def _remove_device(self, device):
        self.dev_list.remove(device)
        del self.keys[device.dev_id]

    @transaction
    def _add_peer_namespace(self, pns):
        self.metadata_keys[psn.ns_id] = b64encode(encrypt_with_cert(pns.pub_key, self.metadata_key))
        self.peer_list.add(pns)
        # allow the peer namespace to access the metadata

    @transaction
    def _remove_peer_namespace(self, pns):
        self.peer_list.remove(pns)
        del self.metadata_keys[pns.ns_id]
        # disallow the peer namespace from accessing the metadata

    @transaction
    def update_metadata(self, new_metadata):
        self.metadata = new_metadata

    def get_peer_namespace(self):
        x509 = X509.load_certificate_from_keychain(self.keychain_path, self.name)
        cert_key = x509.get_PEM_certificate()
        cert = cert_key[0]
        print cert
        self_ns = PeerNS(0, self.name, cert) 
        return self_ns
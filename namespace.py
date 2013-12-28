# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4

"""namespace.py: A Simple namespace implementation for Safe."""
__author__      = "Wathsala Vithanage"
__email__       = "wathsala@princeton.edu"
__copyright__   = "Copyright 2013, Safe Project"
__credits__     = ["Andrew Werner", "Stephen Lin"]
__license__     = "Apache"
__version__     = "0.1"

"""
    1) Provides a primary storage for information of devices owned by the 
       namespace owner.
       Data will be stored according to the JSON format given below.
       {
            "dev_id":       "16-bit ID",
            "dev_name":     "iPhone",
            "int_ts":       "7/20/2013",
            "app_data":     "{Name: Wathsala Vithanage},
                             {Addr: 35, Olden St. Princeton, NJ, 08540}"
       }
    2) Provides a primary storage for information of other namespaces
       that are trusted by this namespace. (alice.bob Alice's namespace refer 
       to bob's namespace)
    3) Do not cache information about devices owned by trusted namespaces.
       Always download the device vector of the trusted namespace before
       name binding happens. (alice.bob.iphone is not cached, always request
       a device list from alice.bob so that we are aware of key revoked device
       keys.
    Note: All primary storages are cacheable on Amazon S3.
"""
import os
import json
import boto
import logging
import copy
from tofu import *

from configuration import Configuration, AWS_USERNAME, AWS_ACCESS_KEY, AWS_SECRET_KEY

from boto import iam
from boto import dynamodb
from boto.dynamodb.exceptions import DynamoDBKeyNotFoundError

from base64 import b64decode, b64encode
from safe_list import SafeList
from device import Device
from peer_ns import PeerNS
from X509 import X509, X509Error
from keychain import encrypt_with_cert
from OpenSSL import crypto
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto import Random

#Setup logging...
logging.basicConfig(format='%(levelname)s:%(message)s')

def transaction(f):
    def wrapped(*args, **kwargs):
        self = args[0]
        if self.conf.local_only:
            return f(*args, **kwargs)

        committed = False
        retries_left = num_retries = 5
        while not committed and retries_left:
            retries_left -= 1
            f(*args, **kwargs)
            new = self.serialize()
            for key, value in new.items():
                if self.serialized.get(key) and self.serialized.get(key) != value:
                    self.serialized[key] = value
            if self.serialized.save():
                committed = True
            else:
                self._reconcile_state()
        if not committed:
            # TODO: better excpetion
            raise Exception("Failed to commit change after %d attempts" % (num_retries,)) 
    return wrapped

class Namespace(object):    
    def __init__(self, conf):
        self.conf = conf
        self.name = conf.aws_conf[AWS_USERNAME]

        if conf.local_only:
            self._init_local()
        else:
            self._init_aws()
        self._reconcile_state()

    def _state_encrypt(self, serialization):
        """returns a base64 encoded AES encrypted copy of serialization"""
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.state_key, AES.MODE_CFB, iv)
        msg = iv + cipher.encrypt(serialization)
        return b64encode(msg)

    def _state_decrypt(self, encrypted):
        """returns a base64 encoded AES encrypted copy of serialization"""
        msg = b64decode(encrypted)
        iv = msg[:AES.block_size]
        cipher = AES.new(self.state_key, AES.MODE_CFB, iv)
        return cipher.decrypt(msg[AES.block_size:])

    def serialize(self):
        """ returns a dictionary representing the serialization of the state of the namespace """
        return {
            'privkey_pem': self._state_encrypt(self.privkey_pem),
            'cert_pem': self._state_encrypt(self.cert_pem),
            'keys': json.dumps(self.keys),
            'ns_list': self._state_encrypt(self.ns_list.serialize()),
            'dev_list': self._state_encrypt(self.dev_list.serialize()),
            'metadata': json.dumps(self.metadata),
        }

    def _init_aws(self):
        aws_conf = self.conf.aws_conf
        self.dynamo = boto.connect_dynamodb(aws_conf[AWS_ACCESS_KEY], aws_conf[AWS_SECRET_KEY])
        self.iam = boto.connect_iam(aws_conf[AWS_ACCESS_KEY], aws_conf[AWS_SECRET_KEY])
        
        response = self.iam.get_user()
        user = response['get_user_response']['get_user_result']['user']
        self.id = user['user_id']

    def _reconcile_state(self):
        if self.conf.local_only:
            return
        namespace_table = self.dynamo.get_table('namespaces')
        try:
            self.serialized = namespace_table.get_item(hash_key=self.id)
        except DynamoDBKeyNotFoundError as e:
            # Initial remote serialization creation
            self.ns_list = SafeList("", cls=PeerNS)
            self.dev_list = SafeList("", cls=Device)
            self.dev_list.add(self.conf.dev)
            self.state_key = Random.new().read(32)
            self.keys = {self.conf.dev.dev_id: b64encode(self.conf.dev_keychain.encrypt(self.state_key))}

            # make a new keypair for the namespace
            pkey = crypto.PKey()
            pkey.generate_key(crypto.TYPE_RSA, 1024)
            x509 = X509(self.id, pkey, 
                    self.conf.aws_conf[AWS_USERNAME],
                    self.conf.user_conf['country'], 
                    self.conf.user_conf['state'], 
                    self.conf.user_conf['city'])
            x509.forge_certificate(False)
            x509.sign_certificate(None)
            rec = x509.get_PEM_certificate()
            self.cert_pem = rec[0]
            self.privkey_pem  = rec[1]

            self.metadata = {}
            self.serialized = namespace_table.new_item(hash_key=self.id, attrs=self.serialize())
            self.serialized.put()
            # rereconcile because we just changed the remote state
            self._reconcile_state()
            return

        # Get the state_key
        self.keys = json.loads(self.serialized['keys'])
        if str(self.conf.dev.dev_id) not in self.keys:
            raise KeyError("Local device ID not found in keys")
        else:
            key = b64decode(self.keys[str(self.conf.dev.dev_id)])
            self.state_key = self.conf.dev_keychain.decrypt(key)

        self.cert_pem = self._state_decrypt(self.serialized['cert_pem'])
        self.privkey_pem = self._state_decrypt(self.serialized['privkey_pem'])

        dec_ns_list = self._state_decrypt(self.serialized['ns_list'])
        if hasattr(self, 'ns_list'):
            self.ns_list.update_from_serialization(dec_ns_list)
        else:  
            self.ns_list = SafeList(dec_ns_list, PeerNS)

        dec_dev_list = self._state_decrypt(self.serialized['dev_list'])
        if hasattr(self, 'dev_list'):
            self.dev_list.update_from_serialization(dec_dev_list)
        else:
            self.dev_list = SafeList(dec_dev_list, Device)

        self.metadata = json.loads(self.serialized['metadata'])

    def _init_local(self):
        self.devl_fd = open(self.conf.dev_list_path, "a+")
        self.nsl_fd = open(self.conf.ns_list_path, "a+")
        self.dev_list = None
        self.ns_list = None
        #Parse the device list and pack them in a set
        try:
            self.dev_list = SafeList(self.devl_fd.read(), cls=Device)
            
        except ValueError as e:
            logging.warning("%s:%s",self.conf.dev_list_path, str(e))
            self.dev_list = SafeList("", cls=Device)

        #Parse the namespace list and pack them in a set
        try:
            self.ns_list = SafeList(self.nsl_fd.read(), cls=PeerNS)

        except ValueError as e:
            logging.warning("%s:%s", self.conf.ns_list_path, str(e))
            self.ns_list = SafeList("", cls=PeerNS)

        self.serialized = {'ns_list': self.ns_list, 'dev_list': self.dev_list}

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        if self.conf.local_only:
            self.sync_local_storage()
            self.devl_fd.close()
            self.nsl_fd.close()

    def sync_local_storage(self):
        if self.conf.local_only:
            self.devl_fd.truncate(0)
            dev_list_json = self.dev_list.serialize()
            self.devl_fd.write(dev_list_json)
            self.nsl_fd.truncate(0)
            ns_list_json = self.ns_list.serialize()
            print ns_list_json
            self.nsl_fd.write(ns_list_json)

    @classmethod
    def join(cls, conf, tofu):
        dev_json_str = json.dumps(conf.dev, cls=Device.ENCODER)
        tofu.send(dev_json_str)
        signed_cert_pem = tofu.receive()
        conf.dev.cert_pem = signed_cert_pem
        conf.dev_keychain.update_keychain(signed_cert_pem)
        ns = cls(conf)
        return ns

    @transaction
    def _add_device(self, device):
        self.dev_list.add(device)
        self.keys[device.dev_id] = b64encode(encrypt_with_cert(device.cert_pem, self.state_key))

    def add_device(self, connection):
        #read the device out from the connection...
        json_dev_str = connection.receive()
        dev = json.loads(json_dev_str, cls=Device.DECODER)
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, self.cert_pem)
        privkey = crypto.load_privatekey(crypto.FILETYPE_PEM, self.privkey_pem)
        dev_x509 = X509.load_certifacate_from_PEM(dev.cert_pem)
        dev_x509.sign_certificate(cert, privkey)
        dev.cert_pem = dev_x509.get_PEM_certificate()[0]
        self._add_device(dev)
        #write the signed certificate dev.cert_pem back to connection 
        connection.send(dev.cert_pem)
        print dev.cert_pem

    def add_peer_namespace(self, connection):
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
        self.ns_list.add(pns)
        # allow the peer namespace to access the metadata

    @transaction
    def _remove_peer_namespace(self, pns):
        self.ns_list.remove(pns)
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

def validate_cert(cacert_pem, cert_pem): 
    from OpenSSL import crypto, SSL
    from Crypto.Util import asn1

    cacert = X509.load_certifacate_from_PEM(cacert_pem).get_certificate()[0]
    cert = X509.load_certifacate_from_PEM(cert_pem).get_certificate()[0]
    sig_algo = cert.get_signature_algorithm()

    # Get the ASN1 format of the certificate
    ASN1_cert = crypto.dump_certificate(crypto.FILETYPE_ASN1, cert)
    # Decode the certificate
    der_seq=asn1.DerSequence()
    der_seq.decode(ASN1_cert)
    der_cert = der_seq[0]
    der_algo = der_seq[1]
    der_sig = asn1.DerObject()
    der_sig.decode(der_seq[2])
    cert_sig_payload = der_sig.payload
    if cert_sig_payload[0]!='\x00':
        raise Exception('Unused bits found!')
    cert_sig = cert_sig_payload[1:]
    # Verify cert with cacert
    try:
        crypto.verify(cacert, cert_sig, der_cert,sig_algo)
        print "Certificate looks good"
    except crypto.Error, e:
        print "Sorry. Nope."

def main():
    conf = Configuration(local_only=False)
    ns = Namespace(conf)

    tc = tofu(input_callback)
    ns.add_device(tc)

    # from OpenSSL import crypto
    # with Namespace(conf) as ns:
    #     #tc = tofu("123456", "safe_device1@is-a-furry.org", "safepassword", "safe_device2@is-a-furry.org")
    #     tc = tofu(input_callback)
    #     ns.add_device(tc)

if __name__ == "__main__":
    main()


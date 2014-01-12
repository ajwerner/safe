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
import uuid
import time
import wget
from configuration      import *
from boto import iam
from boto import dynamodb
from datetime import timedelta, datetime
from boto.dynamodb.exceptions import DynamoDBKeyNotFoundError
from base64             import b64decode, b64encode, urlsafe_b64decode, urlsafe_b64encode
from OpenSSL            import crypto
from Crypto             import Random
from Crypto.Cipher      import AES, PKCS1_OAEP
from Crypto.PublicKey   import RSA
from Crypto.Hash.SHA256 import SHA256Hash
from urllib2       import urlopen, HTTPError
from tofu          import *
from safe_list     import SafeList
from safe_device   import SafeDevice
from peer_ns       import PeerNS
from keychain      import *
from X509          import X509, X509Error

#Setup logging...
logging.basicConfig(format='%(levelname)s:%(message)s')

NUM_RETRIES = 5 # number of times to retry a transaction

def transaction(f):
    def wrapped(*args, **kwargs):
        self = args[0]
        assert(isinstance(self, SafeUser))
        self._reconcile_state()
        committed = False
        retries_left = num_retries = NUM_RETRIES
        while not committed and retries_left:
            retries_left -= 1
            f(*args, **kwargs)
            new = self._serialize()
            for key, value in new.items():
                if self.serialized.get(key) and self.serialized.get(key) != value:
                    self.serialized[key] = value
            committed = self.serialized.save()
            if not committed:
                self._reconcile_state()

        if not committed:
            # TODO: better excpetion
            raise Exception("Failed to commit change after %d attempts" % (num_retries,))
        self._write_logs()
    return wrapped

class AccountCompromisedException(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return str(self.value)

class SafeUser(object):
    # the keys used to sign and verify the state
    STATE_ATTRS = ['privkey_pem', 'cert_pem', 'old_identities', 'state_keys', 'ns_list', 'dev_list', 
                  'metadata_keys', 'metadata', 'uid']
    PROTECTED_METADATA_KEYS = ['cert_pem', 'name', 'email']

    def __init__(self, conf_dir=".safe_config"):
        conf, dev, dev_kc = get_config(conf_dir)
        self.conf = conf
        self.dev = dev
        self.dev_kc = dev_kc
        self.name = self.conf['aws_conf'][AWS_USERNAME]

        # if you can't get in once, see if somebody left you some keys in an S3 bucket
        if not self._init_aws():
            self._fetch_aws_conf_from_S3()
            if not self._init_aws(): # you tried getting new keys but you're still locked out!
                raise Exception("This device appears to have been removed :-(")
        self._reconcile_state()

    def _init_aws(self):
        """
        connects to IAM, dynamodb, and sqs for the user as well as setting the user_id

        may raise on the event of a network error
        """
        aws_conf = self.conf["aws_conf"]
        self.dynamo = boto.connect_dynamodb(aws_conf[AWS_ACCESS_KEY], aws_conf[AWS_SECRET_KEY])
        self.iam = boto.connect_iam(aws_conf[AWS_ACCESS_KEY], aws_conf[AWS_SECRET_KEY])
        self.s3 = boto.connect_s3(aws_conf[AWS_ACCESS_KEY], aws_conf[AWS_SECRET_KEY])
        self.sqs = boto.connect_sqs(aws_conf[AWS_ACCESS_KEY], aws_conf[AWS_SECRET_KEY])
        # will fail if you don't have credentials anymore
        try:
            user_response = self.iam.get_user()
            access_keys_response = self.iam.get_all_access_keys(self.conf['aws_conf'][AWS_USERNAME])
        except:
            return False
        
        # make sure there's only one access key otherwise you can't remove devices and that's bad
        access_keys = access_keys_response\
['list_access_keys_response']['list_access_keys_result']['access_key_metadata']
        if len(access_keys) != 1:
            raise AccountCompromisedException(\
"This account cannot remove devices because an extra set of AWS keys have been created!")
        user = user_response['get_user_response']['get_user_result']['user']
        self.id = user['user_id']
        self.sqs_queue = self.sqs.create_queue(self.id)
        return True

    def _close_aws(self):
        self.iam.close()
        self.s3.close()

    def _fetch_aws_conf_from_S3(self):
        """
        here we're trying to find AWS credentials that were left for 
        """
        today = datetime.today()
        for i in range(1, -11, -1):
            day = today + timedelta(days=i)
            key_str = urlsafe_b64encode(hashlib.sha256(day.strftime("%d/%m/%Y") + self.dev.dev_id).digest())
            url = '/'.join([S3_BASE_URL, S3_DROPBOX_BUCKET, key_str])
            response = None
            try:
                response = urlopen(url).read()
            except HTTPError:
                continue
            credentials_dict = json.loads(response)
            if not credentials_dict.get('key') and credentials_dict.get('contents'):
                raise Exception("Invalid credentials dictionary")
            dev_privkey_pem = self.dev_kc.read_keychain()[1]
            aes_key = decrypt_with_privkey(dev_privkey_pem, b64decode(credentials_dict['key']))
            new_aws_conf = json.loads(AES_decrypt(credentials_dict['contents'], aes_key))
            if not all(key in AWS_CONF_KEYS for key in new_aws_conf):
                raise Exception("Not a valid aws_conf")
            self.conf['aws_conf'] = new_aws_conf
            with open(self.conf['conf_path'], 'w') as conf_file:
                json_string = json.dumps(self.conf)
                conf_file.write(json_string)
            self._init_aws()
            return
        raise Exception("No valid credentials found for this device")

    def _initialize_state(self, namespace_table):
        """ 
        Sets up the user object with the initial values. 
            this function is called when the no database key exists for the user
        """
        # Initial remote serialization creation
        self.uid = b64encode(uuid4().bytes)
        self.peer_list = SafeList("", cls=PeerNS)
        self.dev_list = SafeList("", cls=SafeDevice)
        self.dev_list.add(self.dev)
        self.old_identities = []
        # set up the security on this state
        self._secure_state()
        self.metadata = {'cert_pem': self.cert_pem, 'name': self.name, 'email': self.conf['user_conf']['email']}
        # create the state object in AWS
        self.serialized = namespace_table.new_item(hash_key=self.id, attrs=self._serialize())
        self.serialized.put()
        # rereconcile because we just changed the remote state
        self._reconcile_state()
        return

    def _secure_state(self):
        """ 
        creates a new X509 certificate and state key and sets up the state keys 

        requires that the device list be instantiated and non-empty
        will set the values for state_keys, state_key, cert_pem, and privkey_pem
        """
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

        # set up the state keys
        self.state_key = Random.new().read(32)
        self.state_keys = {}
        for dev in self.get_dev_list():
            self.state_keys[dev.dev_id] = b64encode(encrypt_with_cert(dev.cert_pem, self.state_key))
        self._secure_metadata()

    def _secure_metadata(self):
        self.metadata_key = Random.new().read(32)
        self.metadata_keys = {}
        for peer in self.get_peer_list():
            index = b64encode(hashlib.sha256(peer.cert_pem + peer.local_index).digest())
            self.metadata_keys[index] = b64encode(encrypt_with_cert(peer.cert_pem, self.metadata_key))
        # be careful about these 
        my_index = b64encode(hashlib.sha256(self.cert_pem + self.uid).digest())
        self.metadata_keys[my_index] = b64encode(encrypt_with_cert(self.cert_pem, self.metadata_key))

    def serialize(self):
        """ returns a dictionary representing the serialization of the state of the namespace """
        serialization = {
            'privkey_pem': AES_encrypt(self.privkey_pem, self.state_key),
            'cert_pem': AES_encrypt(self.cert_pem, self.state_key),
            'old_identities': AES_encrypt(json.dumps(self.old_identities), self.state_key),
            'state_keys': json.dumps(self.state_keys),
            'ns_list': AES_encrypt(self.peer_list.serialize(), self.state_key),
            'dev_list': AES_encrypt(self.dev_list.serialize(), self.state_key),
            'metadata_keys': json.dumps(self.metadata_keys),
            'metadata': AES_encrypt(json.dumps(self.metadata), self.metadata_key),
            'uid': AES_encrypt(self.uid, self.state_key),
        }
        # sign this serialization and add it to the state logs
        to_be_signed = json.dumps([key for key, value in sorted(serialization.items()) if key in SafeUser.STATE_ATTRS])
        sig = sign_with_privkey(self.privkey_pem, to_be_signed)
        if not hasattr(self, "logs") or not self.logs:
            self.logs = [sig,]
        elif sig != self.logs[0]:
            self.logs = [sig,] + self.logs
        serialization['logs'] = json.dumps(self.logs)
        return serialization

    def _read_logs(self):
        if not os.path.exists(self.conf['log_path']):
            return []
        with open(self.conf['log_path'], 'r') as log_file:
            return json.load(log_file)

    def _write_logs(self):
        with open(self.conf['log_path'], 'w') as log_file:
            return json.dump(self.logs, log_file)

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

        # Get the state_key
        self.state_keys = json.loads(self.serialized['state_keys'])
        if str(self.dev.dev_id) not in self.state_keys:
            raise KeyError("Local device ID not found in keys")
        else:
            state_key = b64decode(self.state_keys[str(self.dev.dev_id)])
            self.state_key = self.dev_kc.decrypt(state_key)

        # Get the namespace keys
        self.cert_pem = AES_decrypt(self.serialized['cert_pem'], self.state_key)
        self.privkey_pem = AES_decrypt(self.serialized['privkey_pem'], self.state_key)

        # Check the logs
        self.logs = self._read_logs()
        logs = json.loads(self.serialized['logs'])
        for i, sig in enumerate(reversed(self.logs)):
            if logs[-(i+1)] != sig:
                raise AccountCompromisedException("It appears that the SafeUser state has been forked!")

        # verify the state signature
        to_be_verified = json.dumps([key for key, value in sorted(self.serialized.items()) if key in SafeUser.STATE_ATTRS])
        if logs and not verify_signature(self.cert_pem, to_be_verified, logs[0]):
            raise AccountCompromisedException("It appears that the SafeUser state has not been properly signed!")
        self.logs = logs
        self._write_logs()
        self.old_identities = json.loads(AES_decrypt(self.serialized['old_identities'], self.state_key))

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

        # get the uid
        self.uid = AES_decrypt(self.serialized['uid'], self.state_key)

        # get the metadata
        self.metadata_keys = json.loads(self.serialized['metadata_keys'])
        index = b64encode(hashlib.sha256(self.cert_pem+self.uid).digest())
        if index not in self.metadata_keys:
            raise KeyError("Namespace does not have access to its own metadata!")
        else:
            metadata_key = b64decode(self.metadata_keys[index])
            self.metadata_key = decrypt_with_privkey(self.privkey_pem, metadata_key)

        self.metadata = json.loads(AES_decrypt(self.serialized['metadata'], self.metadata_key))

        # drain the message queue and update keys accordningly
        self._drain_message_queue()

    def _drain_message_queue(self):
        messages = self.sqs_queue.get_messages()
        if not messages:
            return
        for message in message:
            message_dict = json.loads(message)
            sender = None
            for peer in self.get_peer_list():
                if peer.id == message_dict['id']:
                    sender = peer
                    break
            if not sender:
                logging.warn("receieved a message from an untrusted/unknown user %s" % message_dict['id'])
            sender_md = self.get_metadata(sender)
            old_sender_md_keys_index = b64encode(hashlib.sha256(sender.cert_pem + sender.local_index).digest())
            del self.metadata_keys[old_sender_md_keys_index]
            sender.cert_pem = sender_md['cert_pem']
            # What do we do about usernames here?
            new_sender_md_keys_index =  b64encode(hashlib.sha256(sender.cert_pem + sender.local_index).digest())
            self.metadata_keys[new_sender_md_keys_index] = b64encode(encrypt_with_cert(sender.cert_pem, self.metadata_key))
        self._reconcile_state()

    def get_metadata(self, peer_user):
        namespace_table = self.dynamo.get_table('namespaces')
        serialized = namespace_table.get_item(hash_key=peer_user.id)
        metadata_keys = json.loads(serialized['metadata_keys'])
        index = b64encode(hashlib.sha256(self.cert_pem + peer_user.remote_index).digest())
        if index in metadata_keys:
            metadata_key = decrypt_with_privkey(self.privkey_pem, b64decode(metadata_keys[index]))
            return json.loads(AES_decrypt(serialized['metadata'], metadata_key))
        for (cert_pem, privkey) in self.old_identities:
            index = b64encode(hashlib.sha256(cert_pem + peer_user.remote_index).digest())
            if index in metadata_keys:
                logging.warn("Using old identity to access %s info" % peer_user.ns_name)
                metadata_key = decrypt_with_privkey(self.privkey_pem, b64decode(metadata_keys[index]))
                return AES_decrypt(serialized['metadata'], metadata_key)
        logging.warn("No access to %s info, removing trust relationship")
        self._remove_peer_namespace(peer_user)

    @transaction
    def _add_device(self, device):
        self.dev_list.add(device)
        self.state_keys[device.dev_id] = b64encode(encrypt_with_cert(device.cert_pem, self.state_key))

    def add_device(self):
        #read the device out from the connection...
        tofu_id = raw_input("Enter a code for this connection: ")
        jabber_id = raw_input("Please enter you gmail username: ")
        jabber_pw = getpass.getpass("Please enter your password: ")
        tofu_connection = tofu(jabber_id, jabber_pw, jabber_id, tofu_id)

        tofu_connection.send(json.dumps(self.conf['aws_conf']))
        tofu_connection.send(json.dumps(self.conf['user_conf']))
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

    def add_peer(self):
        jabber_id = raw_input("Please enter you gmail username: ")
        jabber_pw = getpass.getpass("Please enter your password: ")
        other_id = raw_input("Please enter the other user's gmail username: ")
        tofu_id = raw_input("Enter a connection code (just make sure it's the same on both devices): ")
        connection = tofu(jabber_id, jabber_pw, other_id, tofu_id)
        # read namespace info from the connection...
        ns = self.get_peer_user_object()
        ns.remote_index = b64encode(uuid.uuid4().bytes)
        ns_json = json.dumps(ns, cls=PeerNS.ENCODER)
        connection.send(ns_json)
        peer_ns_json = connection.receive()
        peer_ns = PeerNS(**json.loads(peer_ns_json))
        peer_ns.local_index = ns.remote_index
        # peer_ns_cert_pem = peer_ns.pub_key
        self._add_peer(peer_ns)


    @transaction
    def _add_peer(self, pns):
        index = b64encode(hashlib.sha256(pns.cert_pem + pns.local_index).digest())
        self.metadata_keys[index] = b64encode(encrypt_with_cert(pns.cert_pem, self.metadata_key))
        self.peer_list.add(pns)

    def get_dev_list(self):
        return self.dev_list.get_list()

    def get_peer_list(self):
        return self.peer_list.get_list()

    def remove_device(self, device):
        if self.dev == device:
            raise Exception("you can't remove yourself")
        self._remove_device(device)

        # get new access keys, and put them in the dropbox for everybody else
        new_access_keys_response = self.iam.create_access_key(self.conf['aws_conf'][AWS_USERNAME])
        access_keys_dict = new_access_keys_response['create_access_key_response']['create_access_key_result']['access_key']
        new_aws_conf = {
            AWS_USERNAME: access_keys_dict['user_name'],
            AWS_ACCESS_KEY: access_keys_dict['access_key_id'],
            AWS_SECRET_KEY: access_keys_dict['secret_access_key']
        }
        
        aes_key = Random.new().read(32)
        enc_aws_conf = AES_encrypt(json.dumps(new_aws_conf), aes_key)

        bucket = self.s3.get_bucket(S3_DROPBOX_BUCKET)
        for dev in self.get_dev_list():
            key_str = urlsafe_b64encode(hashlib.sha256(time.strftime("%d/%m/%Y") + dev.dev_id).digest())
            key = bucket.new_key(key_str)
            contents = {"key": b64encode(encrypt_with_cert(dev.cert_pem, aes_key)), 
                        "contents": enc_aws_conf}
            key.set_contents_from_string(json.dumps(contents))
            key.set_acl('public-read')

        old_aws_conf = self.conf['aws_conf']
        self.conf['aws_conf'] = new_aws_conf
        # write the configuration
        with open(self.conf['conf_path'], 'w') as conf_file:
            json_string = json.dumps(self.conf)
            conf_file.write(json_string)
        self.iam.delete_access_key(old_aws_conf[AWS_ACCESS_KEY])
        self._init_aws()

        update_msg = json.dumps({"event": "keys_changed", "id": self.id})
        for peer in self.get_peer_list():
            self.sqs.send_message(peer.id, update_msg)
        # inform the other peers of the removal

    @transaction
    def _remove_device(self, device):
        self.dev_list.remove(device)
        if self.old_identities:
            self.old_identities = [(self.cert_pem, self.privkey_pem)] + self.old_identities
        else:
            self.old_identities = [(self.cert_pem, self.privkey_pem)]
        self._secure_state()

    @transaction
    def _remove_peer_namespace(self, pns):
        self.peer_list.remove(pns)
        self._secure_metadata()

    @transaction
    def update_metadata_key(self, key, value):
        if key in SafeUser.PROTECTED_METADATA_KEYS:
            raise Exception("Cannot update %s in metadata, it is a protected key" % key)
        self.metadata[key] = value

    def get_peer_user_object(self):
        return PeerNS(id=self.id, user_name=self.name, cert_pem=self.cert_pem, ctime=-1, remote_index=None, local_index=None)

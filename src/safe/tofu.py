"""tofu.py: a trust on first use implementation on top of jabber"""
__author__      = "Stephen Lin"
__email__       = "yihsien@princeton.edu"
__copyright__   = "Copyright 2013, Safe Project"
__credits__     = ["Wathsala Vithanage", "Andrew Werner"]
__license__     = "Apache"
__version__     = "0.1"

import sys, xmpp, base64
import hashlib
import threading
from Crypto import Random
from Crypto.Cipher import AES
from diffie_hellman import *

PREFIX_LEN = 5

#handles padding before encryption and unpadding after decryption
BS=16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[0:-ord(s[-1])]

class tofu(object):
 
    def __init__(self, j_id, j_pwd, receiver, tofu_id):
        self.j_id= j_id
        self.j_pwd= j_pwd
        self.receiver= receiver
        self.id = tofu_id
        self.enc=''
        self.msg_queue = []
        self.prefix = base64.b64encode(Random.new().read(PREFIX_LEN))[:PREFIX_LEN]
        self.recv_thread = None
        self.connected = threading.Event()
        self.secured = threading.Event()
        self.lock = threading.RLock()
        self.condition = threading.Condition(self.lock)
        self.condition.acquire(1)
        self.DH = DiffieHellman()
        self._listen()
        self._send(hex(self.DH.publicKey))
        self.condition.wait()
        self.condition.release()

    def __del__(self):
        self.disconnect()

    def _send(self, message):
        text = self.id+self.prefix+message
        self.cl.send(xmpp.protocol.Message(self.receiver, text))

    def _receive(self):
        try:
            if not self.connected.is_set():
              return
            while not self.msg_queue:
              pass
            return self.msg_queue.pop(0)
        except (KeyboardInterrupt, SystemExit):
            sys.exit()

    def _listen(self):
        if self.connected.isSet():
            return
        
        jid = xmpp.protocol.JID(self.j_id)
        cl = xmpp.Client(jid.getDomain(), debug=[])

        con = cl.connect(server=('talk.google.com', 5222))
        if not con:
            raise Exception("could not connect to server")
        auth = cl.auth(jid.getNode(), self.j_pwd,
              resource = jid.getResource())
        if not auth:
          raise Exception("could not authenticate jabber account %s!"
              % self.j_id)
        
        cl.sendInitPresence(requestRoster = 0)
        cl.RegisterHandler('message', self._messageCB)
        self.connected.set()
        self.recv_thread = threading.Thread(target = self.GoOn, args = (cl,))
        self.recv_thread.daemon = True
        self.recv_thread.start()
        self.cl = cl
        return

    def __exit__(self):
        self.connected.clear()
        self.recv_thread.join()            
    
    def _messageCB(self, conn, msg):
        msg_id = msg.getBody()[:len(self.id)]
        msg_prefix = msg.getBody()[len(self.id):len(self.id)+PREFIX_LEN]
        if msg_id != self.id or msg_prefix == self.prefix:
            return
        sender = str(msg.getFrom()).split('/')[0]
        body = msg.getBody()[len(self.id) + PREFIX_LEN:]
        if hasattr(self, "first_message") and body == self.first_message:
            return
        if not self.secured.is_set():
            self.first_message = body
            receiver_pubKey = int(self.first_message, 0)
            self._send(hex(self.DH.publicKey))        
            self.DH.genKey(receiver_pubKey)
            self.secret_value = self.DH.getKey()
            self.secured.set()
            self.condition.notify()
            self.condition.release()
        else:
            body = base64.b64decode(body)
            key=hashlib.sha256(self.secret_value).digest()
            print "Please confirm this seceret value out of bound with the other party: "
            print base64.b64encode(hashlib.sha256(key).digest())[:10]
            iv=body[:AES.block_size]
            cipher = AES.new(key, AES.MODE_CFB, iv)
            msg=cipher.decrypt(body[AES.block_size:])
            self.msg_queue.append(msg)

    def GoOn(self, conn):
        self.condition.acquire()
        try:
            while self.connected.is_set():
                conn.Process(1)
        except:
            self.condition.notify_all()
            self.connected.clear()
        sys.exit()
    
    def send(self, message):
        tojid=self.receiver
        key=hashlib.sha256(self.secret_value).digest()
        iv = Random.new().read(AES.block_size)
        obj=AES.new(key, AES.MODE_CFB, iv)
        text=iv+obj.encrypt(message)
        text=base64.encodestring(text)
        self._send(text)
 


    def receive(self):
        try:
            if not self.connected.is_set():
                return
            while not self.msg_queue:
                pass
            return self.msg_queue.pop(0)
        except (KeyboardInterrupt, SystemExit):
            sys.exit()

    def disconnect(self):
        self.connected.clear()
        self.recv_thread.join()

  

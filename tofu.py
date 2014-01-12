"""tofu.py: a trust on first use implementation on top of jabber"""
__author__      = "Stephen Lin"
__email__       = "yihsien@princeton.edu"
__copyright__   = "Copyright 2013, Safe Project"
__credits__     = ["Wathsala Vithanage", "Andrew Werner"]
__license__     = "Apache"
__version__     = "0.1"

import sys, os, xmpp, time, base64
import hashlib
import getpass
import threading
import time
import random
from Crypto import Random
from Crypto.Cipher import AES
from diffie_hellman import *

#handles padding before encryption and unpadding after decryption
BS=16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[0:-ord(s[-1])]

class tofu(object):
 
    def __init__(self, j_id, j_pwd, receiver):
        self.j_id= j_id
        self.j_pwd= j_pwd
        self.receiver= receiver

        self.enc=''
        self.recv_thread = None
        self.connected = threading.Event()
        self.msg_queue = []
        self.prefix = str(random.randint(1000, 9999))
        print self.prefix
        DH = DiffieHellman()

        self._listen()
        self._send(DH.publicKey)
        self.first_message = self._receive()
        receiver_pubKey = int(self.first_message, 0)
        self._send(DH.publicKey)        

        DH.genKey(receiver_pubKey)
        self.secret_value = DH.getKey()

        self.disconnect()
    
    def _send(self, message):
        tojid = self.receiver
        text = self.prefix+hex(message)
        jid = xmpp.protocol.JID(self.j_id)
        cl = xmpp.Client(jid.getDomain(), debug=[])

        try:
            con = cl.connect(server=('talk.google.com', 5222))
        except IOError as e:
            print e
        if not con:
            print 'could not connect!'
            sys.exit()
        auth = cl.auth(jid.getNode(), self.j_pwd,
                resource = jid.getResource())
        if not auth:
            print 'could not authenticate!'
            sys.exit()

        cl.send(xmpp.protocol.Message(tojid, text))


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

        return

    def __exit__(self):
        self.connected.clear()
        self.recv_thread.join()            
    
    
    def _messageCB(self, conn, msg):
        msg_prefix = msg.getBody()[:len(self.prefix)]
        if msg_prefix == self.prefix:
            return
        sender = str(msg.getFrom()).split('/')[0]
        body = msg.getBody()[4:]
        if hasattr(self, "first_message") and body == self.first_message:
            return
        self.msg_queue.append(body) 
    
    def messageCB(self, conn, msg):
        msg_prefix = msg.getBody()[:4]
        if hasattr(self, "first_message") and msg.getBody() == self.first_message:
            return
        if msg_prefix == self.prefix:
          return
        msg_body = msg.getBody()[4:]
        if msg_body == self.first_message:
            return
        msg_body=base64.b64decode(str(msg_body))
        sender = str(msg.getFrom()).split('/')[0]
        key=hashlib.sha256(self.secret_value).digest()
        iv=msg_body[:16]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        msg=unpad(cipher.decrypt(msg_body[16:]))
        self.msg_queue.append(msg)

    def GoOn(self, conn):
        try:
            while self.connected.is_set():
                conn.Process(1)
        except (KeyboardInterrupt, SystemExit):
            sys.exit()
    
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

    def send(self, message):
        #BS = 16
        #pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
        tojid=self.receiver
        

        #padding the message and encrypting it
        text=pad(message)
        key=hashlib.sha256(self.secret_value).digest()
        iv = Random.new().read(AES.block_size)
        obj=AES.new(key, AES.MODE_CBC, iv)
        text=iv+obj.encrypt(text)
        text=base64.encodestring(text)
        text=self.prefix+text

        jid = xmpp.protocol.JID(self.j_id)
        cl = xmpp.Client(jid.getDomain(), debug=[])

        try:
            con=cl.connect(server=('talk.google.com', 5222))
        except IOError as e:
            print e
        if not con:
            print 'could not connect!'
            sys.exit()
        #print 'connected with', con
        auth = cl.auth(jid.getNode(), self.j_pwd,
                resource=jid.getResource())
        if not auth:
            print 'could not authenticate!'
            sys.exit()
        #print 'authenticated using', auth

        cl.send(xmpp.protocol.Message(tojid,text))
        #cl.disconnect()

    
    def listen(self): 

       if self.connected.isSet():
            return

       jid=xmpp.protocol.JID(self.j_id)
       cl=xmpp.Client(jid.getDomain(),debug=[])

       con=cl.connect(server=('talk.google.com', 5222))
       if not con:
          raise Exception("could not connect to server")
       #print 'connected with', con
       auth=cl.auth(jid.getNode(), self.j_pwd,
       resource=jid.getResource())
       if not auth:
          raise Exception("could not authenticate jabber account %s!" % self.j_id)
       #print 'authenticated using', auth

       cl.sendInitPresence(requestRoster=0)

       cl.RegisterHandler('message', self.messageCB)

       self.connected.set()
       self.recv_thread = threading.Thread(target=self.GoOn, args=(cl,))
       self.recv_thread.daemon = True
       self.recv_thread.start()

       return
        
        
    

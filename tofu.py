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
from Crypto import Random
from Crypto.Cipher import AES

#handles padding before encryption and unpadding after decryption
BS=16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[0:-ord(s[-1])]

def input_callback():
    j_id = raw_input("User ID: ")#+"@is-a-furry.org"
    j_pwd = getpass.getpass("Password: ")
    rcpt = raw_input("To: ")#+"@is-a-furry.org"
    nonce = raw_input("Enter Nonce: ")
    return {'j_id':j_id, 'j_pwd':j_pwd, 'rcpt':rcpt, 'nonce':nonce}

class tofu(object):
 
    #flag = 1
    #enc=''

#  def __init__(self, one_time_pad, j_id, j_pwd, receiver):
    def __init__(self, f):
        rec = f()
        self.one_time_pad = rec['nonce']
        self.j_id= rec['j_id']
        self.j_pwd= rec['j_pwd']
        self.receiver= rec['rcpt']
        self.enc=''
        self.recv_thread = None
        self.connected = threading.Event()
        self.msg_queue = []

    def __exit__(self):
        self.connected.clear()
        self.recv_thread.join()
            
    def messageCB(self, conn, msg):
        msg_body=base64.b64decode(str(msg.getBody()))
        sender = str(msg.getFrom()).split('/')[0]
        key=hashlib.sha256(self.one_time_pad).digest()
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
        key=hashlib.sha256(self.one_time_pad).digest()
        iv = Random.new().read(AES.block_size)
        obj=AES.new(key, AES.MODE_CBC, iv)
        text=iv+obj.encrypt(text)
        text=base64.encodestring(text)

        #jidparams = {}
        #if os.access(os.environ['HOME']+'/.safe_send', os.R_OK):
            #for ln in open(os.environ['HOME']+'/.safe_send').readlines():
                #if not ln[0] in ('#', ';'):
                    #key, val = ln.strip().split('=',1)
                    #jidparams[key.lower()]=val

        #for mandatory in ['jid', 'password']:
            #if mandatory not in jidparams.keys():
                #open(os.environ['HOME']+'/.safe_send',
                        #'w').write('JID=safe_device1@is-a-furry.org\nPASSWORD=safepassword\n')
                #print 'please point ~/.safe_send config file to valid JID for sending messages.'
                #sys.exit(0)

        #jid = xmpp.protocol.JID(jidparams['jid'])
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
        

        #jidparams={}
        #if os.access(os.environ['HOME']+'/.safe_receive', os.R_OK):
            #for ln in open(os.environ['HOME']+'/.safe_receive').readlines():
                #if not ln[0] in ('#', ';'):
                    #key,val=ln.strip().split('=',1)
                    #jidparams[key.lower()]=val
        #for mandatory in ['jid', 'password']:
            #if mandatory not in jidparams.keys():
                #open(os.environ['HOME']+'/.safe_receive','w').write('JID=safe_device2@is-a-furry.org\nPASSWORD=safepassword\n')
                #print 'Please point ~/.safe_receive config file to valid JID receiving messages'
                #sys.exit(0)

        #jid=xmpp.protocol.JID(jidparams['jid'])
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
        #unpad = lambda s : s[0:-ord(s[-1])]


        #time.sleep(1)

        return shared_key

    

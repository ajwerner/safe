"""tofu.py: a trust on first use implementation on top of jabber"""
__author__      = "Stephen Lin"
__email__       = "yihsien@princeton.edu"
__copyright__   = "Copyright 2013, Safe Project"
__credits__     = ["Wathsala Vithanage", "Andrew Werner"]
__license__     = "Apache"
__version__     = "0.1"



import sys, os, xmpp, time, base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES

#handles padding before encryption and unpadding after decryption
BS=16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[0:-ord(s[-1])]

class tofu(object):
 
  #flag = 1
  #enc=''

  def __init__(self, one_time_pad, j_id, j_pwd, receiver):
      self.one_time_pad = one_time_pad
      self.j_id=j_id
      self.j_pwd=j_pwd
      self.receiver=receiver
      self.flag=1
      self.enc=''

  def messageCB(self, conn, msg):
    msg=str(msg.getBody())
    self.enc=base64.decodestring(msg)
    self.flag = 0

  def StepOn(self, conn):
    try:
      conn.Process(1)
    except KeyboardInterrupt:
      return 0
    return self.flag

  def GoOn(self, conn):
    while self.StepOn(conn):
      pass
  
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
      con=cl.connect()
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

  def receive(self):
    

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
    jid=xmpp.protocol.JID(self.j_id)
    cl=xmpp.Client(jid.getDomain(),debug=[])

    con=cl.connect()
    if not con:
      print 'could not connect!'
      sys.exit()
    #print 'connected with', con
    auth=cl.auth(jid.getNode(), self.j_pwd,
      resource=jid.getResource())
    if not auth:
      print 'could not authenticate!'
      sys.exit()
    #print 'authenticated using', auth

    cl.sendInitPresence(requestRoster=0)

    cl.RegisterHandler('message', self.messageCB)

    self.GoOn(cl)

    #unpad = lambda s : s[0:-ord(s[-1])]
    key=hashlib.sha256(self.one_time_pad).digest()
    iv=self.enc[:16]
    obj2 = AES.new(key, AES.MODE_CBC, iv)
    shared_key=unpad(obj2.decrypt(self.enc[16:]))

    #time.sleep(1)

    return shared_key



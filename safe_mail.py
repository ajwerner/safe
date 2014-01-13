__author__      = "Stephen Lin"
__email__       = "yihsien@princeton.edu"
__copyright__   = "Copyright 2013, Safe Project"
__credits__     = ["Wathsala Vithanage", "Andrew Werner"]
__license__     = "Apache"
__version__     = "0.1"

import smtplib
import getpass, imaplib
import email
import random
import ast
from configuration import *
from safe_user import *
#from email.MIMEMultipart import MIMEMultipart
#from email.MIMEText import MIMEText
from email.mime.text import MIMEText
from keychain import *
from Crypto import Random
from Crypto.Cipher import AES

class safe_mail_payload(object):
  def __init__(self, dev_id=None, body=None, key=None, cert=None, sig=None):
    self.dev_id = str(dev_id)
    self.body = str(body)
    self.key = str(key)
    self.cert = str(cert)
    self.sig = str(sig)
class safe_mail(object):

  def send(self, message=False, receiver_addr=False, encrypt=False):
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.ehlo()
    server.starttls()
    server.ehlo()
    #log in to the server
    account = raw_input("Account: ")
    server.login(account, getpass.getpass())

    if not receiver_addr:
      receiver = raw_input("Please enter receiver email address: ")
    else:
      receiver = receiver_addr

    subject = raw_input("Please enter the email subject: ")

    if not message:
      body = raw_input("Please compose the email: ")
    else:
      body = message
    #Send the mail

    msg = MIMEText(body)
    
    
    if encrypt == True:
      #key=hashlib.sha256(str(random.randint(1,10000))).digest()
      #iv = Random.new().read(AES.block_size)
      #obj=AES.new(key, AES.MODE_CFB, iv)
      #body = iv+obj.encrypt(body)
      #body = base64.encodestring(body)

      body = AES_encrypt(body, key)

      s = SafeUser()
      receiver_cert = s.get_metadata(s.get_peer_list()[0])['cert_pem']
      encrypted_key = encrypt_with_cert(receiver_cert, key)
      signature = sign_with_privkey(s.dev_kc.read_keychain()[1], encrypted_key)
      signature = base64.encodestring(signature)     
      
      mail = safe_mail_payload(s.name+"."+s.dev.dev_name, body, encrypted_key,
          s.dev_kc.read_keychain()[0], signature)
      dict_str = str(mail.__dict__)
      msg = MIMEText(dict_str)
    
    #msg = MIMEText(body)
    #msg = MIMEMultipart();
    if encrypt == True:
      msg['Subject'] = "(Safe)-"+subject
    else:
      msg['Subject'] = subject

    msg['From'] = account+"@gmail.com"
    msg['To'] = receiver
    #msg.attach(MIMEText(body, 'plain'))
    text = msg.as_string()
    server.sendmail(account+"@gmail.com", receiver, text)

  def receive(self, safe_only=False):

    s = SafeUser()
    num = input("Please enter how many email you wish to receive: ")
    
    mail = imaplib.IMAP4_SSL('imap.gmail.com')
    mail.login(raw_input("Account: "), getpass.getpass())
    
    mail.select('inbox')
    typ, data = mail.search(None, 'ALL')
    ids = data[0]
    id_list = ids.split()
    #get the most recent email id
    latest_email_id = int( id_list[-1] )

    count = 1
    #iterate messages through descending order
    for i in range( latest_email_id, latest_email_id-num, -1 ):
        typ, data = mail.fetch( i, '(RFC822)' ) 
        for response_part in data:
            if isinstance(response_part, tuple):
                msg = email.message_from_string(response_part[1])
        

        
        subject = msg['Subject']
        #payload = msg.get_payload()
        if not safe_only:
          print "This is mail #%d: " %(count)
          print "Subject: "+subject
          print "Payload:"
          print msg.get_payload()
          count = count + 1
        
        elif subject[:7] == "(Safe)-":
          content = safe_mail_payload(**(ast.literal_eval(msg.get_payload())))
          encrypted_key = content.key
          sender_dev_cert = content.cert
          if not verify_signature(sender_dev_cert, encrypted_key,
              base64.decodestring(content.sig)):
            print "This mail is cannot be verified"
          else:
            key = decrypt_with_privkey(s.privkey_pem, encrypted_key)
            plaintext = AES_decrypt(content.body, key)
            print "This is mail #%d: " %(count)
            print "Subject: "+subject
            print "Payload:"
            print plaintext
            count = count + 1
            print "---------------------  END OF MESSAGE  ---------------------"

    
    mail.close()
    mail.logout() 

  def list_peer():
    return

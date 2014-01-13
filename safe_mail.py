__author__      = "Stephen Lin"
__email__       = "yihsien@princeton.edu"
__copyright__   = "Copyright 2013, Safe Project"
__credits__     = ["Wathsala Vithanage", "Andrew Werner"]
__license__     = "Apache"
__version__     = "0.1"

import smtplib
import getpass, imaplib
import email
from configuration import *
from safe_user import *
#from email.MIMEMultipart import MIMEMultipart
#from email.MIMEText import MIMEText
from email.mime.text import MIMEText
from keychain import *

class mail(object):
  def __init__(self, dev_id, body, key)
    self.dev_id = dev_id
    self.body = body
    self.key = key

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
    
    '''
    if encrypt == True:
      key=hashlib.sha256(random.randin(1,10000).digest()
      iv = Random.new().read(AES.block_size)
      obj=AES.new(key, AES.MODE_CFB, iv)
      body = iv_obj.encrypt(body)
      body = base64.encodestring(body)

      s = SafeUser()
      receiver_cert = None
      encrypt_key = encrypt_with_cert(receiver_cert, key)
      signed_key = sign_with_privkey(s.dev_kc.read_keychain()[1], encrypt_key)
      signed_key = base64.encodestring(signed_key)     
      
      mail = mail(s.name+"."+s.dev.dev_name, body, signed_key)
      dict_str = str(mail.__dict__)
      msg = MIMEText(dict_str)
    '''
    #msg = MIMEText(body)
    #msg = MIMEMultipart(); 
    msg['Subject'] = "(Safe)-"+subject
    msg['From'] = account+"@gmail.com"
    msg['To'] = receiver
    #msg.attach(MIMEText(body, 'plain'))
    text = msg.as_string()
    server.sendmail(account+"@gmail.com", receiver, text)

  def receive(self, safe_only=False):

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
        
        mail = mail(**msg)


        subject = msg['Subject']
        payload = msg.get_payload()
        if not safe_only:
          print "This is mail #%d: " %(count)
          print "Subject: "+subject
          print "Payload:"
          print payload
          count = count + 1
        
        elif subject[:7] == "(Safe)-":
          print "This is mail #%d: " %(count)
          print "Subject: "+subject
          print "Payload:"
          print payload
          count = count + 1

    
    mail.close()
    mail.logout() 

  def list_peer():
    return

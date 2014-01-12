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

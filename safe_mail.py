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

class safe_mail(object):

  def send(self):
    server = smtplib.SMTP('smtp.gmail.com', 587)

    server.starttls()
    #log in to the server
    account = raw_input("Account: ")
    server.login(account, getpass.getpass())
  
    #Send the mail
    msg = "\nHello!" # The /n separates the message from the headers
    
    
    server.sendmail(account+"@gmail.com", 
        raw_input("Please enter receiver email address: "), msg)

  def receive(self):
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
    for i in range( latest_email_id, latest_email_id-2, -1 ):
        typ, data = mail.fetch( i, '(RFC822)' ) 
        for response_part in data:
            if isinstance(response_part, tuple):
                msg = email.message_from_string(response_part[1])
                
        print "This is mail #%d: " %(count)
        #only print out the content
        print msg.get_payload()
        count = count + 1
    
    mail.close()
    mail.logout() 


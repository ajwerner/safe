# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4

"""X509.py: A Simple API for creating and signing X.509 certificates."""
__author__      = "Wathsala Vithanage"
__email__       = "wathsala@princeton.edu"
__copyright__   = "Copyright 2013, Safe Project"
__credits__     = ["Andrew Werner", "Stephen Lin"]
__license__     = "Apache"
__version__     = "0.1"


"""
Class for X.509 certificate creation and signing.
Saves certificates and privates keys to keychain in PEM format.
"""

from OpenSSL import crypto
from Crypto.Util import asn1
import os
import struct

class X509Error:
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return str(self.value)

class X509:

    def __init__(self, dev_id, pkey, ns_name, 
                        country, state, city, cert=None):
        self.pkey       = pkey
        self.dev_C_str  = country
        self.dev_ST_str = state
        self.dev_L_str  = city
        self.dev_id     = dev_id
        self.ns_name    = ns_name
        self.cert       = cert

    def forge_certificate(self, is_self_signed):
        self.dev_OU_str = self.ns_name+".safe"
        self.cert = crypto.X509()
        self.cert.get_subject().C    = self.dev_C_str
        self.cert.get_subject().ST   = self.dev_ST_str
        self.cert.get_subject().L    = self.dev_L_str
        self.cert.get_subject().O    = "safe"
        self.cert.get_subject().OU   = self.dev_OU_str

    def sign_certificate(self, signer_cert, signer_key=None):
        self.serial_number = struct.unpack("Q", os.urandom(8))[0]
        self.cert.set_serial_number(self.serial_number)
        self.cert.gmtime_adj_notBefore(0)
        self.cert.gmtime_adj_notAfter(360*24*60*60*10)

        if signer_cert is None:
            #Self sign the certificate
            if self.dev_id is None:
                self.dev_CN_str = self.ns_name+".safe.com"
            else:
                self.dev_CN_str = "%s.%s.safe.com" % (str(self.dev_id), self.ns_name)
            self.cert.get_subject().CN   = self.dev_CN_str
            self.cert.set_issuer(self.cert.get_subject())
            self.cert.set_pubkey(self.pkey)
            self.cert.sign(self.pkey, 'sha1')
        else:
            self.cert.set_issuer(signer_cert.get_subject())
            self.cert.sign(signer_key, 'sha1')

    @classmethod
    def load_certificate_from_PEM(cls, PEM_cert):
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, PEM_cert)
        return cls(None, None, None, None, None, None, cert)

    def get_certificate(self):
        return self.cert, self.pkey

    def get_PEM_certificate(self):
        cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, self.cert)
        if self.pkey is not None:
            key_pem = crypto.dump_privatekey(crypto.FILETYPE_PEM, self.pkey)
        else:
            key_pem = None
        return cert_pem, key_pem

    def validate_cert(self, cacert_pem): 
        #print cacert_pem
        # Create an X509 object for cacert_pem (CA Certificate).
        cacert = X509.load_certificate_from_PEM(cacert_pem).get_certificate()[0]
        # Get the X509 object of this certifcate.
        cert = self.get_certificate()[0]
        sig_algo = cert.get_signature_algorithm()

        # Let's start with the ASN1 format of this certificate
        ASN1_cert = crypto.dump_certificate(crypto.FILETYPE_ASN1, cert)
        # We need everything in DER format
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
        # Verify this cert with cacert
        try:
            crypto.verify(cacert, cert_sig, der_cert,sig_algo)
            #print "Certifcate Valid!"
            return True
        except crypto.Error as e:
            #print "Certrifcate Invalid: \n"+str(e)
            return False

'''Test X509 class
#Self sign the namespace keys
def _self_sign_ns(namespace):
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 1024)
    try:
        #Create the self signed namespace certficate
        x509 = X509("", k, namespace, "US", "NJ", "Princeton")
        x509.forge_certificate(True)
        x509.sign_certificate(None)
        x509.update_keychain(namespace)
    except X509Error as e:
        print str(e)

#Sign the device keys with the namespace key
def _sign_device(dev_name, namespace):
    #Load certificate for the namespace from the keychain
    x509 = X509.load_certificate_from_keychain(namespace)
    cert_and_key = x509.get_certificate()
    cert = cert_and_key[0]
    key  = cert_and_key[1]
    #Generate a keypair for the device
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 1024)
    #Sign the device key using namespace cert
    try:
        x509_dev = X509(dev_name, k, namespace, "US", "NJ", "Princeton")
        x509_dev.forge_certificate(False)
        x509_dev.sign_certificate(cert, key)
        x509_dev.update_keychain(dev_name+"."+namespace)
    except X509Error as e:
        print str(e)

#Self sign the namespace
_self_sign_ns("wathsala")
#sign the device Dev0
_sign_device("Dev0", "wathsala")
'''

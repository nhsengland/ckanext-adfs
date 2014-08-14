"""
Validation related functions.
"""
import base64
import lxml.etree as ET
from StringIO import StringIO
from M2Crypto import EVP, RSA, X509, m2


def verify_signature(signed_info, cert, signature):
    """
    Coordinates the actual verification of the signature.
    """
    x509 = X509.load_cert_string(base64.decodestring(cert), X509.FORMAT_DER)
    pubkey = x509.get_pubkey().get_rsa()
    verify_EVP = EVP.PKey()
    verify_EVP.assign_rsa(pubkey)
    verify_EVP.reset_context(md='sha256')
    verify_EVP.verify_init()
    verify_EVP.verify_update(signed_info)
    return verify_EVP.verify_final(signature.decode('base64'))


def get_signature(doc):
    """
    Ahahahahahahahaahahaha..!

    Someone, somewhere is killing an XML kitten.
    """
    return [z for z in
               [y for y in
                   [x for x in doc if
                   x.tag.endswith('RequestedSecurityToken')][0]]
                [0]
            if z.tag.endswith('Signature')][0]


def get_signed_info(signature):
    """
    Gets the block of XML that constitutes the signed entity. Ensures it
    returns a string representation of said XML that has undergone c14n
    (canonicalisation) cleanup with the exclusive flag set to True (this is
    why we need to use LXML).
    """
    signed_info = signature.find(
            '{http://www.w3.org/2000/09/xmldsig#}SignedInfo')
    signed_info_str = ET.tostring(signed_info, method='c14n', exclusive=True)
    return signed_info_str


def get_cert(signature):
    """
    Gets the certificate from the eggsmell.
    """
    ns = '{http://www.w3.org/2000/09/xmldsig#}'
    keyinfo = signature.find('{}KeyInfo'.format(ns))
    keydata = keyinfo.find('{}X509Data'.format(ns))
    certelem = keydata.find('{}X509Certificate'.format(ns))
    return certelem.text


def get_signature_value(signature):
    """
    Get the signature from the eggsmell.
    """
    return signature.find(
            '{http://www.w3.org/2000/09/xmldsig#}SignatureValue').text


def validate_saml(saml):
    """
    Given a string representation of a SAML response will return a boolean
    indication of if it's cryptographically valid (i.e. the signature
    validates).
    """
    xml = ET.fromstring(saml)
    signature = get_signature(xml)
    signed_info = get_signed_info(signature)
    cert = get_cert(signature)
    signature_value = get_signature_value(signature)
    is_valid = verify_signature(signed_info, cert, signature_value)
    return is_valid==1


if __name__ == '__main__':
    with open('test.xml') as raw:
        eggsmell = raw.read()
    print parse_saml(eggsmell)

"""
Validation related functions.
"""
import base64
import xml.etree.ElementTree as ET
from StringIO import StringIO
from M2Crypto import EVP, RSA, X509, m2
from ElementC14N import parse


def verify_signature(signed_info, cert, signature):
    x509 = X509.load_cert_string(base64.decodestring(cert), X509.FORMAT_DER)
    pubkey = x509.get_pubkey().get_rsa()
    verify_EVP = EVP.PKey()
    verify_EVP.assign_rsa(pubkey)
    verify_EVP.reset_context(md='sha1')
    verify_EVP.verify_init()
    verify_EVP.verify_update(signed_info)
    return verify_EVP.verify_final(signature.decode('base64'))


def get_signature(doc):
    """
    ahahahahahahahaahahaha fuck..!
    """
    return [z for z in [y for y in [x for x in doc if x.tag.endswith('RequestedSecurityToken')][0]][0] if z.tag.endswith('Signature')][0]


def get_signed_info(signature):
    signed_info = signature.find(
            '{http://www.w3.org/2000/09/xmldsig#}SignedInfo')
    signed_info_str = ET.tostring(signed_info)
    parsed = parse(StringIO(signed_info_str))
    return ET.tostring(parsed.getroot())
    #return signed_info_str


def get_cert(signature):
    ns = '{http://www.w3.org/2000/09/xmldsig#}'
    keyinfo = signature.find('{}KeyInfo'.format(ns))
    keydata = keyinfo.find('{}X509Data'.format(ns))
    certelem = keydata.find('{}X509Certificate'.format(ns))
    return certelem.text


def get_signature_value(signature):
    return signature.find(
            '{http://www.w3.org/2000/09/xmldsig#}SignatureValue').text


def parse_saml(saml):
    xml = ET.fromstring(saml)
    signature = get_signature(xml)
    import pdb; pdb.set_trace()
    signed_info = get_signed_info(signature)
    cert = get_cert(signature)
    signature_value = get_signature_value(signature)
    is_valid = verify_signature(signed_info, cert, signature_value)
    return is_valid


with open('test.xml') as raw:
    eggsmell = raw.read()
print parse_saml(eggsmell)

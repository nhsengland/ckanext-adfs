"""
Validation related functions.
"""
import logging
import base64
import lxml.etree as ET
from M2Crypto import EVP, X509


log = logging.getLogger(__name__)


def get_tag(doc, tagname):
    """
    Assume that we don't care about namespaces or painful XML xpath search.
    """
    for t in doc.iter('*'):
        if t.tag.endswith(tagname):
            return t
    return None


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
    Get's the tag that includes the security token (signature).
    """
    return get_tag(doc, 'RequestedSecurityToken')


def get_signed_info(signature):
    """
    Gets the block of XML that constitutes the signed entity. Ensures it
    returns a string representation of said XML that has undergone c14n
    (canonicalisation) cleanup with the exclusive flag set to True (this is
    why we need to use LXML).
    """
    signed_info = get_tag(signature, 'SignedInfo')
    signed_info_str = ET.tostring(signed_info, method='c14n', exclusive=True)
    return signed_info_str


def get_cert(signature):
    """
    Gets the certificate from the eggsmell.
    """
    certelem = get_tag(signature, 'X509Certificate')
    return certelem.text


def get_signature_value(signature):
    """
    Get the signature from the eggsmell.
    """
    return get_tag(signature, 'SignatureValue').text


def validate_saml(saml, x509_certificates):
    """
    Given a string representation of a SAML response will return a boolean
    indication of if it's cryptographically valid (i.e. the signature
    validates). The x509_certificates argument is a set containing string
    representations of the expected valid certificates that could be referenced
    in the incoming SAML.
    """
    try:
        xml = ET.fromstring(saml)
        signature = get_signature(xml)
        signed_info = get_signed_info(signature)
        cert = get_cert(signature)
        if cert not in x509_certificates:
            # Ensure the SAML certificate is one of the valid ones provided
            # by the metadata.
            return False
        signature_value = get_signature_value(signature)
        is_valid = verify_signature(signed_info, cert, signature_value)
        if is_valid != 1:
            # To save some time in the future when we need to see broken SAML.
            log.error('INVALID SAML')
            log.error(saml)
        return is_valid==1
    except Exception as ex:
        # Log this for later consumption.
        log.error('ADFS validation error')
        log.error(saml)
        log.error(ex)
        return False

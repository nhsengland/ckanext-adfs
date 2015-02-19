"""
Ensures the validation of the SAML response from the ADFS service works as
expected.
"""
import os
import inspect
import unittest
import mock
import lxml
import lxml.etree as ET
from ckanext.adfs import validation
from ckanext.adfs.metadata import get_certificates


# WTF are we..?
PATH_TO_FILES = os.path.dirname(inspect.getfile(inspect.currentframe()))


# There is also a response.old.xml that used to be used.
VALID_SAML = open('{}/response.new.xml'.format(PATH_TO_FILES), 'rb').read()


# There is also a FederationMetadata.old.xml that used to be used.
X509 = get_certificates(open('{}/FederationMetadata.new.xml'.format(PATH_TO_FILES), 'rb').read())


class TestValidation(unittest.TestCase):
    """
    Tests the various functions within the validation module.
    """

    def test_get_tag(self):
        """
        Ensures we're able to get a tag while ignoring namespaces.
        """
        doc = ET.fromstring('<xml><foo xmlns:t="http://schemas.xmlsoap.org/ws/2005/02/trust"><bar>baz</bar></foo></xml>')
        result = validation.get_tag(doc, 'bar')
        self.assertEqual('bar', result.tag)
        self.assertIsInstance(result, ET._Element)

    def test_get_signature(self):
        """
        Ensures that given a valid DOM will return the element representing
        the Signature tag.
        """
        dom = ET.fromstring(VALID_SAML)
        result = validation.get_signature(dom)
        self.assertIsInstance(result, ET._Element)
        self.assertEqual('{http://www.w3.org/2000/09/xmldsig#}Signature',
                         result.tag)

    def test_get_signed_info(self):
        """
        Ensures the fragment of the DOM that is the information that is
        signed can be obtained FROM the DOM.
        """
        dom = ET.fromstring(VALID_SAML)
        signature = validation.get_signature(dom)
        result = validation.get_signed_info(signature)
        self.assertIsInstance(result, str)

    def test_get_signed_info_c14n_exclusive(self):
        """
        Ensures that the method for generating the string is generated with
        the correct function for canonicalization with the exclusive flag set
        to True.
        """
        with mock.patch.object(validation.ET, 'tostring') as mock_call:
            dom = ET.fromstring(VALID_SAML)
            signature = validation.get_signature(dom)
            validation.get_signed_info(signature)
            signed_info = signature.find(
                        '{http://www.w3.org/2000/09/xmldsig#}SignedInfo')
            mock_call.assert_called_once_with(signed_info, method='c14n',
                                              exclusive=True)

    def test_get_cert(self):
        """
        Ensures that we're able to extract the certificate from the signature
        fragment.
        """
        dom = ET.fromstring(VALID_SAML)
        signature = validation.get_signature(dom)
        result = validation.get_cert(signature)
        self.assertIsInstance(result, str)

    def test_get_signature_value(self):
        """
        Ensures that we're able to get the string representation of the
        signature.
        """
        dom = ET.fromstring(VALID_SAML)
        signature = validation.get_signature(dom)
        result = validation.get_signature_value(signature)
        self.assertIsInstance(result, str)

    def test_verify_signature(self):
        """
        Given various valid inputs, ensures the signature is verfied as
        correct.
        """
        dom = ET.fromstring(VALID_SAML)
        signature = validation.get_signature(dom)
        signed_info = validation.get_signed_info(signature)
        cert = validation.get_cert(signature)
        signature_value = validation.get_signature_value(signature)
        is_valid = validation.verify_signature(signed_info, cert,
                                               signature_value)
        self.assertEqual(1, is_valid)

    def test_verify_signature_with_bad_data(self):
        """
        Give some invalid inputs, ensures the signature is shown to be
        incorrect.
        """
        dom = ET.fromstring(VALID_SAML)
        signature = validation.get_signature(dom)
        signed_info = validation.get_signed_info(signature)
        cert = validation.get_cert(signature)
        signature_value = validation.get_signature_value(signature)
        signature_value = 'WRONG' + signature_value[5:]
        is_valid = validation.verify_signature(signed_info, cert,
                                               signature_value)
        self.assertEqual(0, is_valid)

    def test_validate_saml(self):
        """
        Ensure that a valid response returns True
        """
        self.assertTrue(validation.validate_saml(VALID_SAML, X509))

    def test_validate_saml_with_certificate_mismatch(self):
        """
        Ensures that while the certificate in the incoming SAML may be valid,
        it must match the expected certificate passed into the method.
        """
        bad_certs = set(['bad', 'certificates'])
        self.assertFalse(validation.validate_saml(VALID_SAML, bad_certs))

    def test_validate_saml_with_non_xml(self):
        """
        Ensure that a response that doesn't contain XML merely returns False
        and the associated exception is logged.
        """
        with mock.patch('ckanext.adfs.validation.log.error') as mock_logger:
            result = validation.validate_saml("Hello world!", X509)
            self.assertEqual(3, mock_logger.call_count)
            self.assertFalse(result)

    def test_validate_saml_with_invalid_xml(self):
        """
        Ensure that a response that contains invalid but well formed XML
        returns False and the associated exception is logged.
        """
        with mock.patch('ckanext.adfs.validation.log.error') as mock_logger:
            result = validation.validate_saml("<xml/>", X509)
            self.assertEqual(3, mock_logger.call_count)
            self.assertFalse(result)

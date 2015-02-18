"""
Ensures the functions relating to grabbing and processing metadata assocaited
with ADFS work as expected.
"""
import os
import inspect
import unittest
import mock
import lxml.etree as ET
from ckanext.adfs.metadata import (get_certificates, get_federation_metadata,
                                   get_wsfed)


# There is also a FederationMetadata.old.xml that used to be used.
PATH_TO_METADATA = os.path.dirname(inspect.getfile(inspect.currentframe()))
METADATA = open('{}/FederationMetadata.new.xml'.format(PATH_TO_METADATA),
                'rb').read()


class TestValidation(unittest.TestCase):
    """
    Tests the various functions within the validation module.
    """

    def test_get_certificates(self):
        """
        We should get two certificates given the content of METADATA.
        """
        result = get_certificates(METADATA)
        self.assertEqual(2, len(result))
        cert_list = list(result)
        for cert in cert_list:
            # Check they're actually the certificates we're interested in.
            self.assertTrue(cert.startswith('MII'))

    def test_get_certificates_not_XML(self):
        """
        Since we're parsing a value from an external third party, ensure we
        recover gracefully from crap-in.
        """
        # Mocking the log ensures we know the exception has been handled.
        with mock.patch('ckanext.adfs.metadata.log.error') as mock_logger:
            result = get_certificates('not xml')
            self.assertEqual(3, mock_logger.call_count)
            self.assertEqual(set(), result)

    def test_get_certificates_wrong_XML(self):
        """
        The incoming value is valid XML but not the correct XML. It should
        handle that!
        """
        result = get_certificates('<xml/>')
        self.assertEqual(set(), result)

    def test_get_federation_metadata(self):
        """
        Ensures that an attempt to get the Federation Metadata from the url
        is handled properly in the good case.
        """
        mock_response = mock.MagicMock()
        mock_response.status_code = 200
        mock_response.text = METADATA
        with mock.patch('requests.get',
                        return_value=mock_response) as mock_get:
            url = 'http://my_url.com'
            result = get_federation_metadata(url)
            self.assertEqual(result, METADATA)
            mock_get.assert_called_once_with(url)

    def test_get_federation_metadata_server_error(self):
        """
        Ensure the expected ValueError exception is raised if we don't get a
        valid response.
        """
        mock_response = mock.MagicMock()
        mock_response.status_code = 404
        mock_response.text = METADATA
        with mock.patch('requests.get',
                        return_value=mock_response) as mock_get:
            with self.assertRaises(ValueError) as raised:
                url = 'http://my_url.com'
                result = get_federation_metadata(url)
                mock_get.assert_called_once_with(url)
                self.assertEqual(raised.exception.args[0],
                                 'Metadata response: 404')

    def test_get_wsfed_(self):
        """
        Given some valid XML expressed as a string the function should return
        a single string that is the WSFED endpoint.
        """
        result = get_wsfed(METADATA)
        self.assertEqual('https://login.windows.net/03159e92-72c6-4b23-a64a-af50e790adbf/wsfed', result)

    def test_get_wsfed_not_XML(self):
        """
        Since we're parsing a value from an external third party, ensure we
        recover gracefully from crap-in.
        """
        # Mocking the log ensures we know the exception has been handled.
        with mock.patch('ckanext.adfs.metadata.log.error') as mock_logger:
            result = get_wsfed('not xml')
            self.assertEqual(3, mock_logger.call_count)
            self.assertEqual('', result)

    def test_get_wsfed_wrong_XML(self):
        """
        The incoming value is valid XML but not the correct XML. It should
        handle that!
        """
        result = get_wsfed('<xml/>')
        self.assertEqual('', result)

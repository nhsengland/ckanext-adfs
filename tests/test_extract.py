"""
Ensures user details can be extracted from the SAML response from the ADFS
service.
"""
import os
import inspect
import unittest
import mock
from ckanext.adfs.extract import get_user_info


# WTF are we..?
PATH_TO_FILES = os.path.dirname(inspect.getfile(inspect.currentframe()))


# There is also a response.old.xml that used to be used.
VALID_SAML = open('{}/response.new.xml'.format(PATH_TO_FILES), 'rb').read()


class TestGetUserInfo(unittest.TestCase):
    """
    Ensures the get_user_info function works as expected.
    """

    def test_good_saml(self):
        """
        We have valid SAML with the expected fields in it. We should get back
        the expected information.
        """
        username, email, firstname, surname = get_user_info(VALID_SAML)
        self.assertEqual('mohammed_khaliq', username)
        self.assertEqual('mohammed.khaliq@england.nhs.uk', email)
        self.assertEqual('Mohammed', firstname)
        self.assertEqual('Khaliq', surname)

    def test_no_user_details(self):
        """
        Given some valid XML that doesn't contain the expected tags just
        return empty values.
        """
        empty_xml = '<xml/>'
        username, email, firstname, surname = get_user_info(empty_xml)
        self.assertEqual(None, username)
        self.assertEqual(None, email)
        self.assertEqual(None, firstname)
        self.assertEqual(None, surname)

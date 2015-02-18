"""
Ensures the validation of the SAML response from the ADFS service works as
expected.
"""
import unittest
import mock
import lxml
import lxml.etree as ET
from ckanext.adfs import validation

VALID_SAML = open('not.pretty.xml', 'rb').read()


#VALID_SAML = """<t:RequestSecurityTokenResponse xmlns:t="http://schemas.xmlsoap.org/ws/2005/02/trust"><t:Lifetime><wsu:Created xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">2014-08-13T13:11:59.228Z</wsu:Created><wsu:Expires xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">2014-08-14T01:11:59.228Z</wsu:Expires></t:Lifetime><wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy"><EndpointReference xmlns="http://www.w3.org/2005/08/addressing"><Address>http://openhealthcare.org.uk/omg/signins</Address></EndpointReference></wsp:AppliesTo><t:RequestedSecurityToken><Assertion ID="_22bb7bdb-b74c-4d6e-962a-f3bcab63f560" IssueInstant="2014-08-13T13:11:59.306Z" Version="2.0" xmlns="urn:oasis:names:tc:SAML:2.0:assertion"><Issuer>https://sts.windows.net/274d6cd3-fc99-4513-b32a-a1b548d2f09c/</Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" /><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" /><ds:Reference URI="#_22bb7bdb-b74c-4d6e-962a-f3bcab63f560"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" /><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" /></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" /><ds:DigestValue>qRKd2ApDV4yQPq9q34LNSNMYxHJcko7wgv+qQDvgDLg=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>WlgSv04FwMNqoB5ap5nOnaRd5ctgzxg1/0sVvFBOnybnpDVaF8nCfBbhuj07TvqiI5uEllur7i1QrcId6p8bvfumYK30LEDocV6c17gSoJHh7ftMTaQxLGmiwnbVH/Lj+rwO1shKQWM9aHF1SvjWiS032cHdC35Wpff7ZObQ4JEUVSKVZ03xRa//wY9T2UHDlrnJzKYKHfXskfSXLTY5Wx5Qx705MHSisrkUm35yhI3cgFH8x4ayd14QcB9/6O8skXEgQvIETZGcN+l/+ED6sUObmcE+Q1/1mfganMyqXSlYmCsnKgiYXM9599U5HPMdUFhE5ulSe4YkT3iFmhbemA==</ds:SignatureValue><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>MIIDPjCCAiqgAwIBAgIQsRiM0jheFZhKk49YD0SK1TAJBgUrDgMCHQUAMC0xKzApBgNVBAMTImFjY291bnRzLmFjY2Vzc2NvbnRyb2wud2luZG93cy5uZXQwHhcNMTQwMTAxMDcwMDAwWhcNMTYwMTAxMDcwMDAwWjAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkSCWg6q9iYxvJE2NIhSyOiKvqoWCO2GFipgH0sTSAs5FalHQosk9ZNTztX0ywS/AHsBeQPqYygfYVJL6/EgzVuwRk5txr9e3n1uml94fLyq/AXbwo9yAduf4dCHTP8CWR1dnDR+Qnz/4PYlWVEuuHHONOw/blbfdMjhY+C/BYM2E3pRxbohBb3x//CfueV7ddz2LYiH3wjz0QS/7kjPiNCsXcNyKQEOTkbHFi3mu0u13SQwNddhcynd/GTgWN8A+6SN1r4hzpjFKFLbZnBt77ACSiYx+IHK4Mp+NaVEi5wQtSsjQtI++XsokxRDqYLwus1I1SihgbV/STTg5enufuwIDAQABo2IwYDBeBgNVHQEEVzBVgBDLebM6bK3BjWGqIBrBNFeNoS8wLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldIIQsRiM0jheFZhKk49YD0SK1TAJBgUrDgMCHQUAA4IBAQCJ4JApryF77EKC4zF5bUaBLQHQ1PNtA1uMDbdNVGKCmSf8M65b8h0NwlIjGGGy/unK8P6jWFdm5IlZ0YPTOgzcRZguXDPj7ajyvlVEQ2K2ICvTYiRQqrOhEhZMSSZsTKXFVwNfW6ADDkN3bvVOVbtpty+nBY5UqnI7xbcoHLZ4wYD251uj5+lo13YLnsVrmQ16NCBYq2nQFNPuNJw6t3XUbwBHXpF46aLT1/eGf/7Xx6iy8yPJX4DyrpFTutDz882RWofGEO5t4Cw+zZg70dJ/hH/ODYRMorfXEW+8uKmXMKmX2wyxMKvfiPbTy5LmAU8Jvjs2tLg4rOBcXWLAIarZ</X509Certificate></X509Data></KeyInfo></ds:Signature><Subject><NameID>vKAFA9vj9knfclZdI2H7Ua1mQihXilzD6fCyeCrIHfc</NameID><SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer" /></Subject><Conditions NotBefore="2014-08-13T13:11:59.228Z" NotOnOrAfter="2014-08-14T01:11:59.228Z"><AudienceRestriction><Audience>http://openhealthcare.org.uk/omg/signins</Audience></AudienceRestriction></Conditions><AttributeStatement><Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"><AttributeValue>OMG</AttributeValue></Attribute><Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"><AttributeValue>Testing</AttributeValue></Attribute><Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"><AttributeValue>testing@nhsenglandtest.onmicrosoft.com</AttributeValue></Attribute><Attribute Name="http://schemas.microsoft.com/identity/claims/tenantid"><AttributeValue>274d6cd3-fc99-4513-b32a-a1b548d2f09c</AttributeValue></Attribute><Attribute Name="http://schemas.microsoft.com/identity/claims/objectidentifier"><AttributeValue>f720dacc-e034-452d-8b2c-6f3682f48525</AttributeValue></Attribute><Attribute Name="http://schemas.microsoft.com/identity/claims/identityprovider"><AttributeValue>https://sts.windows.net/274d6cd3-fc99-4513-b32a-a1b548d2f09c/</AttributeValue></Attribute></AttributeStatement><AuthnStatement AuthnInstant="2014-08-13T13:11:58.000Z"><AuthnContext><AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</AuthnContextClassRef></AuthnContext></AuthnStatement></Assertion></t:RequestedSecurityToken><t:RequestedAttachedReference><SecurityTokenReference d3p1:TokenType="http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0" xmlns:d3p1="http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd" xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"><KeyIdentifier ValueType="http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLID">_22bb7bdb-b74c-4d6e-962a-f3bcab63f560</KeyIdentifier></SecurityTokenReference></t:RequestedAttachedReference><t:RequestedUnattachedReference><SecurityTokenReference d3p1:TokenType="http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0" xmlns:d3p1="http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd" xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"><KeyIdentifier ValueType="http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLID">_22bb7bdb-b74c-4d6e-962a-f3bcab63f560</KeyIdentifier></SecurityTokenReference></t:RequestedUnattachedReference><t:TokenType>http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0</t:TokenType><t:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</t:RequestType><t:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</t:KeyType></t:RequestSecurityTokenResponse>"""

X509 = 'MIIC4jCCAcqgAwIBAgIQQNXrmzhLN4VGlUXDYCRT3zANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE0MTAyODAwMDAwMFoXDTE2MTAyNzAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALyKs/uPhEf7zVizjfcr/ISGFe9+yUOqwpel38zgutvLHmFD39E2hpPdQhcXn4c4dt1fU5KvkbcDdVbP8+e4TvNpJMy/nEB2V92zCQ/hhBjilwhF1ETe1TMmVjALs0KFvbxW9ZN3EdUVvxFvz/gvG29nQhl4QWKj3x8opr89lmq14Z7T0mzOV8kub+cgsOU/1bsKqrIqN1fMKKFhjKaetctdjYTfGzVQ0AJAzzbtg0/Q1wdYNAnhSDafygEv6kNiquk0r0RyasUUevEXs2LY3vSgKsKseI8ZZlQEMtE9/k/iAG7JNcEbVg53YTurNTrPnXJOU88mf3TToX14HpYsS1ECAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAfolx45w0i8CdAUjjeAaYdhG9+NDHxop0UvNOqlGqYJexqPLuvX8iyUaYxNGzZxFgGI3GpKfmQP2JQWQ1E5JtY/n8iNLOKRMwqkuxSCKJxZJq4Sl/m/Yv7TS1P5LNgAj8QLCypxsWrTAmq2HSpkeSk4JBtsYxX6uhbGM/K1sEktKybVTHu22/7TmRqWTmOUy9wQvMjJb2IXdMGLG3hVntN/WWcs5w8vbt1i8Kk6o19W2MjZ95JaECKjBDYRlhG1KmSBtrsKsCBQoBzwH/rXfksTO9JoUYLXiW0IppB7DhNH4PJ5hZI91R8rR0H3/bKkLSuDaKLWSqMhozdhXsIIKvJQ=='


#X509 = """MIIDPjCCAiqgAwIBAgIQsRiM0jheFZhKk49YD0SK1TAJBgUrDgMCHQUAMC0xKzApBgNVBAMTImFjY291bnRzLmFjY2Vzc2NvbnRyb2wud2luZG93cy5uZXQwHhcNMTQwMTAxMDcwMDAwWhcNMTYwMTAxMDcwMDAwWjAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkSCWg6q9iYxvJE2NIhSyOiKvqoWCO2GFipgH0sTSAs5FalHQosk9ZNTztX0ywS/AHsBeQPqYygfYVJL6/EgzVuwRk5txr9e3n1uml94fLyq/AXbwo9yAduf4dCHTP8CWR1dnDR+Qnz/4PYlWVEuuHHONOw/blbfdMjhY+C/BYM2E3pRxbohBb3x//CfueV7ddz2LYiH3wjz0QS/7kjPiNCsXcNyKQEOTkbHFi3mu0u13SQwNddhcynd/GTgWN8A+6SN1r4hzpjFKFLbZnBt77ACSiYx+IHK4Mp+NaVEi5wQtSsjQtI++XsokxRDqYLwus1I1SihgbV/STTg5enufuwIDAQABo2IwYDBeBgNVHQEEVzBVgBDLebM6bK3BjWGqIBrBNFeNoS8wLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldIIQsRiM0jheFZhKk49YD0SK1TAJBgUrDgMCHQUAA4IBAQCJ4JApryF77EKC4zF5bUaBLQHQ1PNtA1uMDbdNVGKCmSf8M65b8h0NwlIjGGGy/unK8P6jWFdm5IlZ0YPTOgzcRZguXDPj7ajyvlVEQ2K2ICvTYiRQqrOhEhZMSSZsTKXFVwNfW6ADDkN3bvVOVbtpty+nBY5UqnI7xbcoHLZ4wYD251uj5+lo13YLnsVrmQ16NCBYq2nQFNPuNJw6t3XUbwBHXpF46aLT1/eGf/7Xx6iy8yPJX4DyrpFTutDz882RWofGEO5t4Cw+zZg70dJ/hH/ODYRMorfXEW+8uKmXMKmX2wyxMKvfiPbTy5LmAU8Jvjs2tLg4rOBcXWLAIarZ"""

class TestValidation(unittest.TestCase):
    """
    Tests the various functions within the validation module.
    """

    def setUp(self):
        """
        """
        pass

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
        self.assertFalse(validation.validate_saml(VALID_SAML, X509+'bad'))

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

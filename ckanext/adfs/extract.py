"""
Utility function[s] for extracting user information from incoming SAML
responses.
"""


import lxml.etree as ET


def get_user_info(saml):
    """
    Given a SAML response will attempt to extract and return the user's
    username, email address, firstname and surname as a tuple. If no values
    can be found then a tuple containing None values will be returned.
    """
    root = ET.fromstring(saml)
    # Honestly..!
    attributes = [tag for tag in root.iter('*')
                  if tag.tag.endswith('Attribute')]
    email = None
    firstname = None
    surname = None
    username = None
    for attr in attributes:
        if attr.attrib['Name'].endswith('givenname'):
            firstname = attr[0].text
        elif attr.attrib['Name'].endswith('surname'):
            surname = attr[0].text
        elif attr.attrib['Name'].endswith('emailaddress'):
            email = attr[0].text

    username = email

    return (username, email, firstname, surname)

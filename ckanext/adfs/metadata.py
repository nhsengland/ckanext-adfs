"""
Metadata handling functions.
"""
import logging
import requests
import lxml.etree as ET


log = logging.getLogger(__name__)


def get_certificates(metadata):
    """
    Given some metadata expressed as a string of Eggsmell, will extract the
    correct certificates found therein and return them as strings in a set.
    """
    type_path = '{http://www.w3.org/2001/XMLSchema-instance}type'
    key_descriptor_path = '{urn:oasis:names:tc:SAML:2.0:metadata}KeyDescriptor'
    try:
        dom = ET.fromstring(str(metadata))
        for child in list(dom):
            service_type = child.attrib.get(type_path, None)
            if service_type == 'fed:ApplicationServiceType':
                return set([x.xpath('string()') for x in
                           child.findall(key_descriptor_path)])
    except Exception as ex:
        # Do the sensible thing and log what went wrong.
        log.error('UNABLE TO PARSE CERTIFICATE METADATA')
        log.error(metadata)
        log.error(ex)
    return set()


def get_federation_metadata(url):
    """
    Grabs the XML from the specified endpoint url.
    """
    response = requests.get(url)
    if response.status_code < 400:
        return response.text.replace(u'\ufeff', '')
    else:
        raise ValueError('Metadata response: {}'.format(response.status_code))


def get_wsfed(metadata):
    """
    Given some metadata expressed as a string of XML, will extract the correct
    Passive Requestor Endpoint (also known as WSFED).
    """
    type_path = '{http://www.w3.org/2001/XMLSchema-instance}type'
    wsfed_path = '{http://docs.oasis-open.org/wsfed/federation/200706}PassiveRequestorEndpoint'
    try:
        dom = ET.fromstring(str(metadata))
        for child in list(dom):
            service_type = child.attrib.get(type_path, None)
            if service_type == 'fed:ApplicationServiceType':
                tag = child.find(wsfed_path)
                if tag is not None:
                    return tag.xpath('string()')
    except Exception as ex:
        # Do the sensible thing and log what went wrong.
        log.error('UNABLE TO PARSE WSFED METADATA')
        log.error(metadata)
        log.error(ex)
    return ''

ckanext-adfs
------------

A CKAN extension for validating users against Microsoft's Active Directory
Federated Services API.

See the requirements.txt file for third party modules needed for this to
work (lxml and M2Crypto).

Development Environment:
=======================

Create a new virtualenv and install the requirements with the `pip` command::

    $ mkvirtualenv foo
    (foo)$ pip install -r requirements.txt

Alternatively, make sure you've installed the requirements in CKAN's own
virtualenv.

To run the test suite type::

    $ python -m unittest discover

All the heavy lifting for checking the response is done in the `validation`
module.

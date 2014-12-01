ckanext-adfs
------------

A CKAN extension for validating users against Microsoft's Active Directory
Federated Services (ADFS) API.

See the requirements.txt file for third party modules needed for this to
work (lxml and M2Crypto).

Configure:
=========

In Azure ensure the following settings are correct for your application:

* Sign-on URL - should be https://yourdomain.com/user/login (replacing <yourdomain> with, er, your domain).
* Reply URL - should be https://yourdomain.com/adfs/signin/ (make sure you include the trailing slash).

On the machine hosting your instance of CKAN:

Ensure all the requirements are installed (see `requirements.txt` for further
details).

In your CKAN's settings.ini file you need to provide two settings in the
[app:main] section:

* adfs_wtrealm - the `APP ID URI` setting found in the "Get Started" / "Enable Users to Sign On" section on the "home" page for the application integrating with ADFS on the Azure website. This is usually the same as the APP ID URI you define in the settings for the application.

* adfs_federation_metadata_path - a path to a local copy of the The ADFS_NAMESPACE and adfs_x509 related values can be found in the `FederationMetadata.xml` file associated with the application integrating with ADFS. This file can be downloaded from the URL in the "Federation Metadata Document URL" value also in the "Enable Users to Sign On" section

*A WORD OF WARNING* Microsoft appears to change its UI in the Azure website quite often so you may need to poke around to find the correct settings.

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

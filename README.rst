ckanext-adfs
------------

A CKAN extension for validating users against Microsoft's Active Directory
Federated Services (ADFS) Single Sign On (SSO) API.

See the requirements.txt file for third party modules needed for this to
work (lxml and M2Crypto). You'll also need the following packages installed:

 * libxml2
 * libxml2-dev
 * libxslt1.1
 * libxslt1-dev
 * openssl
 * libssl-dev
 * swig
 * python-dev

What is ADFS?
============

Microsoft's Azure cloud-based offering provides Active Directory Federated
Services (ADFS for short). As far as we can tell these have absolutely nothing
to do with the "traditional" LDAP/ActiveDirectory we love to loath but is a
confusion thought up by their marketing department. In essence it is possible
to create an "Active Director" within Azure to define groups of users. ADFS
is a way to allow such users to log in to some third party application (in this
case it's your instance of CKAN) via your Azure active directory. For this to
happen you'll need to create a new "application" (representing your CKAN
instance) within the relevant Azure active directory. Microsoft have good
documentation online for doing this.

If you merely want to test this extension you can take out a free trial at the
Azure website (although you'll need to provide credit card details to prove
you're not a bot).

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

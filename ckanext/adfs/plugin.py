"""
Plugin for our ADFS
"""
import logging
import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
import pylons
import uuid
from validation import validate_saml
from metadata import get_certificates, get_federation_metadata, get_wsfed
from extract import get_user_info


log = logging.getLogger(__name__)


# Some awful XML munging.
WSFED_ENDPOINT = ''
WTREALM = pylons.config['adfs_wtrealm']
METADATA = get_federation_metadata(pylons.config['adfs_metadata_url'])
WSFED_ENDPOINT = get_wsfed(METADATA)


if not (WSFED_ENDPOINT):
    raise ValueError('Unable to read WSFED_ENDPOINT values for ADFS plugin.')


def adfs_authentication_endpoint():
    url_template = '{}?wa=wsignin1.0&wreq=xml&wtrealm={}'
    return url_template.format(WSFED_ENDPOINT, WTREALM)


def is_adfs_user():
    return pylons.session.get('adfs-user')


class ADFSPlugin(plugins.SingletonPlugin):
    """
    Log us in via the ADFSes
    """
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.ITemplateHelpers)
    plugins.implements(plugins.IRoutes)
    plugins.implements(plugins.IAuthenticator)

    def update_config(self, config):
        """
        Add our templates to CKAN's search path
        """
        toolkit.add_template_directory(config, 'templates')

    def get_helpers(self):
        return dict(is_adfs_user=is_adfs_user,
                    adfs_authentication_endpoint=adfs_authentication_endpoint)

    def before_map(self, map):
        """
        Called before the routes map is generated. ``before_map`` is before any
        other mappings are created so can override all other mappings.

        :param map: Routes map object
        :returns: Modified version of the map object
        """
        # Route requests for our WAAD redirect URI to a custom controller.
        map.connect(
            'adfs_redirect_uri', '/adfs/signin/',
            controller='ckanext.adfs.plugin:ADFSRedirectController',
            action='login')
        return map

    def after_map(self, map):
        """
        Called after routes map is set up. ``after_map`` can be used to
        add fall-back handlers.

        :param map: Routes map object
        :returns: Modified version of the map object
        """
        return map

    def identify(self):
        """
        Called to identify the user.
        """
        user = pylons.session.get('adfs-user')
        if user:
            toolkit.c.user = user

    def login(self):
        """
        Called at login.
        """
        pass

    def logout(self):
        """
        Called at logout.
        """
        keys_to_delete = [key for key in pylons.session
                          if key.startswith('adfs')]
        if keys_to_delete:
            for key in keys_to_delete:
                del pylons.session[key]
            pylons.session.save()


    def abort(self, status_code, detail, headers, comment):
        """
        Called on abort.  This allows aborts due to authorization issues
        to be overriden.
        """
        return (status_code, detail, headers, comment)


def _get_user(name):
    """
    Return the CKAN user with the given user name, or None.
    """
    try:
        return toolkit.get_action('user_show')(data_dict = {'id': name})
    except toolkit.ObjectNotFound:
        return None


class FileNotFoundException(Exception):
    pass


class ADFSRedirectController(toolkit.BaseController):
    """
    A custom home controller for receiving ADFS authorization responses.
    """

    def login(self):
        """
        Handle eggsmell request from the ADFS redirect_uri.
        """
        eggsmell = pylons.request.POST['wresult']
        # We grab the metadata for each login because due to opaque
        # bureaucracy and lack of communication the certificates can be
        # changed. We looked into this and took made the call based upon lack
        # of user problems and tech being under our control vs the (small
        # amount of) latency from a network call per login attempt.
        metadata = get_federation_metadata(pylons.config['adfs_metadata_url'])
        x509_certificates = get_certificates(metadata)
        if not validate_saml(eggsmell, x509_certificates):
            raise ValueError('Invalid signature')
        username, email, firstname, surname = get_user_info(eggsmell)

        if not email:
            log.error('Unable to login with ADFS')
            log.error(eggsmell)
            raise ValueError('No email returned with ADFS')

        user = _get_user(username)
        if user:
            # Existing user
            log.info('Logging in from ADFS with user: {}'.format(username))
        else:
            # New user, so create a record for them.
            log.info('Creating user from ADFS')
            log.info('email: {} firstname: {} surname: {}'.format(email,
                     firstname.encode('utf8'), surname.encode('utf8')))
            log.info('Generated username: {}'.format(username))
            # TODO: Add the new user to the NHSEngland group? Check this!
            user = toolkit.get_action('user_create')(
                context={'ignore_auth': True},
                data_dict={'name': username,
                           'fullname': firstname + ' ' + surname,
                           'password': str(uuid.uuid4()),
                           'email': email})
        pylons.session['adfs-user'] = username
        pylons.session['adfs-email'] = email
        pylons.session.save()
        toolkit.redirect_to(controller='user', action='dashboard', id=email)
        return

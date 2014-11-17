"""
Plugin for our ADFS
"""
import logging
import lxml.etree as ET
import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
import pylons
import uuid
from validation import validate_saml

log = logging.getLogger(__name__)


def adfs_authentication_endpoint():
    url = pylons.config['adfs_authentication_endpoint']
    return url

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
        return dict(adfs_authentication_endpoint=adfs_authentication_endpoint)

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
        if not validate_saml(eggsmell):
            raise ValueError('Invalid signature')
        root = ET.fromstring(eggsmell)
        # Honestly..!
        attributes = [z for z in
                         [y for y in
                             [x for x in root if
                                 x.tag.endswith('RequestedSecurityToken')][0]
                         ][0]
                      if z.tag.endswith('AttributeStatement')][0]

        email = None
        firstname = None
        surname = None
        for a in attributes:
            if a.attrib['Name'].endswith('givenname'):
                firstname = a[0].text
            elif a.attrib['Name'].endswith('surname'):
                surname = a[0].text
            elif a.attrib['Name'].endswith('claims/name'):
                email = a[0].text

        username = email.split('@', 1)[0].replace('.', '_').lower()
        user = _get_user(username)
        if user:
            log.info('Logging in from ADFS with user: {}'.format(username))
        else:
            log.info('Creating user from ADFS')
            log.info('email: {} firstname: {} surname: {}'.format(email,
                     firstname, surname))
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
        toolkit.redirect_to(controller='user', action='dashboard',
                            id=email)
        return

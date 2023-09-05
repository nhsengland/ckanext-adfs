"""
Plugin for our ADFS
"""
import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
import ckan.logic.schema
from ckan.common import session
from ckanext.adfs import schema
from six import text_type

from metadata import get_federation_metadata, get_wsfed
try:
    from ckan.common import config
except ImportError:
    from pylons import config


# Some awful XML munging.
WSFED_ENDPOINT = ''
WTREALM = config['adfs_wtrealm']
METADATA = get_federation_metadata(config['adfs_metadata_url'])
WSFED_ENDPOINT = get_wsfed(METADATA)
AUTH_URL_TEMPLATE = config.get('adfs_url_template','{}?wa=wsignin1.0&wreq=xml&wtrealm={}')


if not (WSFED_ENDPOINT):
    raise ValueError('Unable to read WSFED_ENDPOINT values for ADFS plugin.')


def adfs_authentication_endpoint():
    try:
        auth_endpoint = AUTH_URL_TEMPLATE.format(WSFED_ENDPOINT, WTREALM)
    except:
        auth_endpoint = '{}?wa=wsignin1.0&wreq=xml&wtrealm={}'.format(WSFED_ENDPOINT, WTREALM)
    return auth_endpoint


def is_adfs_user():
    return session.get('adfs-user')


class ADFSPlugin(plugins.SingletonPlugin):
    """
    Log us in via the ADFSes
    """
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.ITemplateHelpers)
    plugins.implements(plugins.IRoutes)
    plugins.implements(plugins.IAuthenticator)

    def update_config(self, config_):
        """
        Add our templates to CKAN's search path
        """
        ckan.logic.schema.user_new_form_schema = schema.user_new_form_schema
        ckan.logic.schema.user_edit_form_schema = schema.user_edit_form_schema
        ckan.logic.schema.default_update_user_schema = schema.default_update_user_schema
        toolkit.add_template_directory(config_, 'templates')
        toolkit.add_resource('fanstatic', 'adfs')

    def update_config_schema(self, schema):
        ignore_missing = toolkit.get_validator('ignore_missing')
        ignore_not_sysadmin = toolkit.get_validator('ignore_not_sysadmin')

        schema.update({
            # This is a custom configuration option
            'login_button_name': [ignore_missing, ignore_not_sysadmin, text_type],
            'login_page_title': [ignore_missing, ignore_not_sysadmin, text_type],
            'new_page_title': [ignore_missing, ignore_not_sysadmin, text_type],
            'login_page_description': [ignore_missing, ignore_not_sysadmin, text_type],
            'new_page_description': [ignore_missing, ignore_not_sysadmin, text_type]
        })

        return schema

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
        # Route requests for our WAAD redirect URI to a custom controller
        map.connect(
            'adfs_redirect_uri', '/adfs/signin/',
            controller='ckanext.adfs.controller:ADFSRedirectController',
            action='login')
        # Route password reset requests to a custom controller
        map.connect(
            'adfs_request_reset', '/user/reset',
            controller='ckanext.adfs.controller:ADFSUserController',
            action='request_reset')
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
        Get user from repoze.who cookie.
        """
        environ = toolkit.request.environ
        user = None
        if 'repoze.who.identity' in environ:
            user = environ['repoze.who.identity']['repoze.who.userid']
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
        keys_to_delete = [key for key in session
                          if key.startswith('adfs')]
        if keys_to_delete:
            for key in keys_to_delete:
                del session[key]
            session.save()

    def abort(self, status_code, detail, headers, comment):
        """
        Called on abort.  This allows aborts due to authorization issues
        to be overriden.
        """
        return (status_code, detail, headers, comment)

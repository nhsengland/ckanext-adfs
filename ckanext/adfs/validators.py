import re
from ckan.common import _
from ckan.model import PACKAGE_NAME_MAX_LENGTH
from ckan.lib.navl.dictization_functions import Invalid
from profanityfilter import ProfanityFilter


name_match = re.compile('[a-z0-9_\-]*$')
def adfs_name_validator(value, context):
    """
    Custom validator for usernames
    ADFS users have email addresses as usernames
    """
    if not isinstance(value, basestring):
        raise Invalid(_('Names must be strings'))

    # check basic textual rules
    if value in ['new', 'edit', 'search']:
        raise Invalid(_('That name cannot be used'))

    if len(value) < 2:
        raise Invalid(_('Must be at least %s characters long') % 2)
    if len(value) > PACKAGE_NAME_MAX_LENGTH:
        raise Invalid(_('Name must be a maximum of %i characters long') % \
                      PACKAGE_NAME_MAX_LENGTH)

    # ADFS users can not change their username
    if is_adfs_user(value, context):
        return value

    if not name_match.match(value):
        raise Invalid(_('Must be purely lowercase alphanumeric '
                        '(ascii) characters and these symbols: -_'))
    return value


def adfs_user_name_sanitize(key, data, errors, context):
    # Non-ADFS users need to sanitize their username
    username = context.get('user')
    if not is_adfs_user(username, context):
        invalid_name = ['admin', 'manage', 'root']
        value = data[key]
        if is_input_valid(value) is False:
            raise Invalid(_('Input Contains Invalid Text'))
        for invalid_string in invalid_name:
            if value and re.match(invalid_string, value, re.IGNORECASE):
                raise Invalid(_('Input Contains Invalid Text'))


def adfs_user_about_validator(key, data, errors, context):
    value = data[key]
    if is_input_valid(value) is False:
        raise Invalid(_('Input Contains Invalid Text'))


def is_input_valid(input_value):
    invalid_list = ['hacked', 'hacking', 'hacks', 'hack[^a-zA-Z]+', 'malware', 'virus']
    pf = ProfanityFilter()

    for invalid_string in invalid_list:
        if re.search(invalid_string, input_value, re.IGNORECASE):
            return False
    if not pf.is_clean(input_value):
        return False
    return True


def is_adfs_user(username, context):
    if not username:
        username = context.get('user')
    # ADFS users have email addresses as usernames
    if re.match("[^@]+@[^@]+\.[^@]+", username, re.IGNORECASE):
        model = context['model']
        user = model.User.by_name(username)
        # ADFS users do not have passwords
        if user:
            if user.is_active() and not user.password:
                return True
    return False

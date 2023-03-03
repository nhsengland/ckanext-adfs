import json
import re
import six
import string
from ckan import authz
from ckan.common import _
from ckan.lib.navl.dictization_functions import Missing, Invalid
from ckan.model import PACKAGE_NAME_MAX_LENGTH
from profanityfilter import ProfanityFilter


MIN_PASSWORD_LENGTH = 10
MIN_RULE_SETS = 2
MIN_LEN_ERROR = (
    'Your password must be {} characters or longer, and consist of at least '
    '{} of the following character sets: uppercase characters, lowercase '
    'characters, digits, punctuation & special characters.'
)


def adfs_user_password_validator(key, data, errors, context):
    value = data[key]

    if isinstance(value, Missing):
        pass
    elif not isinstance(value, six.string_types):
        raise Invalid(_('Passwords must be strings.'))
    elif value == '':
        pass
    else:
        rules = [
            any(x.isupper() for x in value),
            any(x.islower() for x in value),
            any(x.isdigit() for x in value),
            any(x in string.punctuation for x in value)
        ]
        if len(value) < MIN_PASSWORD_LENGTH or sum(rules) < MIN_RULE_SETS:
            raise Invalid(_(MIN_LEN_ERROR.format(MIN_PASSWORD_LENGTH, MIN_RULE_SETS)))


def adfs_old_username_validator(key, data, errors, context):
    # Prevents changing of user names
    user_id = data.get(('id',))
    old_user = context['model'].User.get(user_id)
    new_user_name = data[key]
    if old_user.name != new_user_name:
        if is_adfs_user(old_user.name, context):
            raise Invalid(_('Unauthorized to change user name'))
        if not authz.is_sysadmin(context.get('user')):
            raise Invalid(_('Unauthorized to change user name'))
    return old_user.name


def adfs_user_name_sanitize(key, data, errors, context):
    value = data[key]
    if is_input_valid(value) is False:
        raise Invalid(_('Input contains invalid text'))
    elif value and re.match('admin', value, re.IGNORECASE):
        raise Invalid(_('Input contains invalid text'))
    elif value and re.match('edit', value, re.IGNORECASE):
        raise Invalid(_('Input contains invalid text'))
    elif value and re.match('me', value, re.IGNORECASE):
        raise Invalid(_('Input contains invalid text'))


invalid_list = [
    'activity', 'delete', 'follow', 'followers', 'generate_key', 'hack',
    'login', 'logged_in', 'logged_out', 'logged_out_redirect',
    'malware', 'register', 'reset', 'root', 'set_lang', 'unfollow', 'virus',
    '_logout',
]
def is_input_valid(input_value):
    value = input_value.lower()
    pf = ProfanityFilter()
    for invalid_string in invalid_list:
        if re.search(invalid_string, value, re.IGNORECASE):
            return False
    if not pf.is_clean(value):
        return False
    return True


name_match = re.compile('[a-z0-9_\-]*$')
def adfs_name_validator(value, context):
    '''
    Custom validator for usernames
    ADFS users have email addresses as usernames
    '''
    if not isinstance(value, six.string_types):
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


def adfs_password_validator(key, data, errors, context):
    '''
    ADFS users do not have passwords and can not reset passwords
    '''
    model = context['model']
    user = context.get('user')

    password = data.get(('password',),None)

    password1 = data.get(('password1',),None)
    password2 = data.get(('password2',),None)

    if password and is_adfs_user(user, context):
        raise Invalid(_('Unauthorized to set password'))

    if password1 and password1 == password2 and is_adfs_user(user, context):
        raise Invalid(_('Unauthorized to set password'))


def is_adfs_user(username, context):
    '''
    ADFS users have email addresses as usernames
    '''
    if not username:
        username = context.get('user')
    if re.match("[^@]+@[^@]+\.[^@]+", username, re.IGNORECASE):
        model = context['model']
        user = model.User.by_name(username)
        if user:
            if user.is_active() and not user.password:
                return True
    return False


def json_object(value):
    '''
    Make sure value can be serialized as a JSON object
    '''
    if value is None or value == '':
        return
    try:
        if not json.dumps(value).startswith('{'):
            raise Invalid(_('The value should be a valid JSON object'))
    except ValueError as e:
        raise Invalid(_('Could not parse the value as a valid JSON object'))

    return value

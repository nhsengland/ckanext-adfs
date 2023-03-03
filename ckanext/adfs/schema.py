from ckantoolkit import unicode_safe

from ckan.lib.navl.validators import ignore, ignore_missing, not_empty
from ckan.logic.validators import (
    ignore_not_sysadmin,
    user_about_validator,
    user_both_passwords_entered,
    user_name_validator,
    user_password_not_empty,
    user_passwords_match,
    email_validator
)
from ckanext.adfs.validators import (
    adfs_user_password_validator,
    adfs_old_username_validator,
    adfs_user_name_sanitize,
    adfs_name_validator,
    adfs_password_validator,
    json_object
)


def default_user_schema():
    """
    Custom schema to validate users
    """
    schema = {
        'id': [ignore_missing, unicode_safe],
        'name': [not_empty, adfs_name_validator, user_name_validator,
                 adfs_user_name_sanitize, unicode_safe],
        'fullname': [ignore_missing, unicode_safe],
        'password': [adfs_user_password_validator, user_password_not_empty,
                     ignore_missing, unicode_safe],
        'password_hash': [ignore_missing, ignore_not_sysadmin, unicode_safe],
        'email': [not_empty, unicode_safe, email_validator],
        'about': [ignore_missing, user_about_validator, unicode_safe],
        'created': [ignore],
        'openid': [ignore_missing],
        'sysadmin': [ignore_missing, ignore_not_sysadmin],
        'apikey': [ignore],
        'reset_key': [ignore],
        'activity_streams_email_notifications': [ignore_missing],
        'state': [ignore_missing],
        'image_url': [ignore_missing, unicode_safe],
        'image_display_url': [ignore_missing, unicode_safe],
        'plugin_extras': [ignore_missing, json_object, ignore_not_sysadmin]
    }
    return schema


def user_new_form_schema():
    schema = default_user_schema()

    schema['name'] = [not_empty, adfs_name_validator, user_name_validator,
                      adfs_user_name_sanitize, unicode_safe]
    schema['fullname'] = [ignore_missing, adfs_user_name_sanitize, unicode_safe]
    schema['about'] = [ignore_missing, user_about_validator, unicode_safe]
    schema['password1'] = [unicode_safe, user_both_passwords_entered,
                           adfs_user_password_validator, user_passwords_match]
    schema['password2'] = [unicode_safe]

    return schema


def user_edit_form_schema():
    schema = default_user_schema()

    schema['name'] = [ignore_missing, adfs_name_validator, user_name_validator,
                      adfs_user_name_sanitize, adfs_old_username_validator, unicode_safe]
    schema['fullname'] = [ignore_missing, adfs_user_name_sanitize, unicode_safe]
    schema['about'] = [ignore_missing, user_about_validator, unicode_safe]
    schema['password'] = [ignore_missing]
    schema['password1'] = [ignore_missing, unicode_safe, adfs_user_password_validator,
                           user_passwords_match, adfs_password_validator]
    schema['password2'] = [ignore_missing, unicode_safe]

    return schema


def default_update_user_schema():
    schema = default_user_schema()

    schema['name'] = [ignore_missing, adfs_name_validator,
                      user_name_validator, unicode_safe]
    schema['password'] = [ignore_missing, adfs_user_password_validator,
                          adfs_password_validator, unicode_safe]
    return schema

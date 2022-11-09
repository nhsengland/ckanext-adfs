# encoding: utf-8

import logging
import ckan.lib.helpers as h
import ckan.model as model
import ckan.plugins.toolkit as toolkit
import base64
from validation import validate_saml
from metadata import get_certificates, get_federation_metadata
from extract import get_user_info
import ckan.lib.base as base
import ckan.logic as logic
import ckan.lib.mailer as mailer
from ckan.common import _, c, request, session
from ckan.controllers.user import UserController


log = logging.getLogger(__name__)
render = base.render
check_access = logic.check_access
get_action = logic.get_action
NotFound = logic.NotFound
NotAuthorized = logic.NotAuthorized


class ADFSRedirectController(toolkit.BaseController):
    """
    A custom home controller for receiving ADFS authorization responses.
    """

    def login(self):
        """
        Handle eggsmell request from the ADFS redirect_uri.
        """
        try:
            eggsmell = toolkit.request.POST.get('wresult')
            if not eggsmell:
                request_data = dict(toolkit.request.POST)
                eggsmell = base64.decodestring(request_data['SAMLResponse'])
        except:
            log.info('ADFS eggsmell')
            log.info(dict(toolkit.request.POST))
        # We grab the metadata for each login because due to opaque
        # bureaucracy and lack of communication the certificates can be
        # changed. We looked into this and took made the call based upon lack
        # of user problems and tech being under our control vs the (small
        # amount of) latency from a network call per login attempt.
        metadata = get_federation_metadata(toolkit.config['adfs_metadata_url'])
        x509_certificates = get_certificates(metadata)
        if not validate_saml(eggsmell, x509_certificates):
            raise ValueError('Invalid signature')
        username, email, firstname, surname = get_user_info(eggsmell)

        if not email:
            log.error('Unable to login with ADFS')
            log.error(eggsmell)
            raise ValueError('No email returned with ADFS')

        user = model.User.by_name(username)
        if user:
            if not user.is_active():
                # Deleted user
                log.error('Unable to login with ADFS, {} was deleted'.format(username))
                h.flash_error('This CKAN account was deleted and is no longer accessible.')
                toolkit.redirect_to(controller='user', action='login')
            else:
                # Existing user
                log.info('Logging in from ADFS with username: {}'.format(username))
        else:
            # New user, so create a record for them.
            log.info('Creating user from ADFS, username: {}'.format(username))
            user = model.User(name=username)
            user.sysadmin = False

        # Update fullname
        if firstname and surname:
            user.fullname = firstname + ' ' + surname
        # Update mail
        if email:
            user.email = email

        # Save the user in the database
        model.Session.add(user)
        model.Session.commit()
        model.Session.remove()

        session['adfs-user'] = username
        session['adfs-email'] = email
        session.save()

        '''Set the repoze.who cookie to match a given user_id'''
        if u'repoze.who.plugins' in toolkit.request.environ:
            rememberer = toolkit.request.environ[u'repoze.who.plugins'][u'friendlyform']
            identity = {u'repoze.who.userid': username}
            headers = rememberer.remember(toolkit.request.environ, identity)
            for header, value in headers:
                toolkit.response.headers.add(header, value)

        toolkit.redirect_to(controller='user', action='dashboard', id=email)
        return


class ADFSUserController(UserController):
    def request_reset(self):
        context = {'model': model, 'session': model.Session, 'user': c.user,
                   'auth_user_obj': c.userobj}
        data_dict = {'id': request.params.get('user')}
        try:
            check_access('request_reset', context)
        except NotAuthorized:
            abort(403, _('Unauthorized to request reset password.'))

        if request.method == 'POST':
            id = request.params.get('user')

            context = {'model': model,
                       'user': c.user}

            data_dict = {'id': id}
            user_obj = None
            try:
                user_dict = get_action('user_show')(context, data_dict)
                user_obj = context['user_obj']
            except NotFound:
                # Try searching the user
                del data_dict['id']
                data_dict['q'] = id

                if id and len(id) > 2:
                    user_list = get_action('user_list')(context, data_dict)
                    if len(user_list) == 1:
                        # This is ugly, but we need the user object for the
                        # mailer,
                        # and user_list does not return them
                        del data_dict['q']
                        data_dict['id'] = user_list[0]['id']
                        user_dict = get_action('user_show')(context, data_dict)
                        user_obj = context['user_obj']
                    elif len(user_list) > 1:
                        h.flash_error(_('"%s" matched several users') % (id))
                    else:
                        h.flash_error(_('No such user: %s') % id)
                else:
                    h.flash_error(_('No such user: %s') % id)

            if user_obj:
                # Don't reset password for ADFS users
                if user_obj.password is None:
                    h.flash_error(_('Could not reset password for user: %s') % id)
                    return render('user/request_reset.html')
                # Send reset link
                try:
                    mailer.send_reset_link(user_obj)
                    h.flash_success(_('Please check your inbox for '
                                    'a reset code.'))
                    h.redirect_to('/')
                except mailer.MailerException as e:
                    h.flash_error(_('Could not send reset link: %s') %
                                  text_type(e))
        return render('user/request_reset.html')

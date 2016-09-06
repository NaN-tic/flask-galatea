#This file is part galatea blueprint for Flask.
#The COPYRIGHT file at the top level of this repository contains
#the full copyright notices and license terms.
from flask import Blueprint, request, render_template, current_app, session, \
    jsonify, redirect, url_for, flash, abort, g
from flask.ext.babel import gettext as _, lazy_gettext as __
from flask.ext.mail import Mail, Message
from flask.ext.wtf import Form
from wtforms import TextField, PasswordField, SelectField, HiddenField, validators
from .tryton import tryton
from .signals import login as slogin, failed_login as sfailed_login, logout as slogout
from .helpers import login_required, manager_required
from trytond.transaction import Transaction

import stdnum.eu.vat as vat
import random
import string

try:
    import hashlib
except ImportError:
    hashlib = None
    import sha

portal = Blueprint('portal', __name__, template_folder='templates')

GALATEA_WEBSITE = current_app.config.get('TRYTON_GALATEA_SITE')
REGISTRATION_VAT = current_app.config.get('REGISTRATION_VAT')
REGISTRATION_VAT_CHECK_CUSTOMER = current_app.config.get(
    'REGISTRATION_VAT_CHECK_CUSTOMER', False)
DEFAULT_COUNTRY = current_app.config.get('DEFAULT_COUNTRY')
REDIRECT_AFTER_LOGIN = current_app.config.get('REDIRECT_AFTER_LOGIN')
REDIRECT_AFTER_LOGOUT = current_app.config.get('REDIRECT_AFTER_LOGOUT')
LOGIN_EXTRA_FIELDS = current_app.config.get('LOGIN_EXTRA_FIELDS', [])

GalateaUser = tryton.pool.get('galatea.user')
Website = tryton.pool.get('galatea.website')
Party = tryton.pool.get('party.party')
ContactMechanism = tryton.pool.get('party.contact_mechanism')
Subdivision = tryton.pool.get('country.subdivision')

VAT_COUNTRIES = [('', '')]
for country in sorted(vat.country_codes):
    VAT_COUNTRIES.append((country, country.upper()))


class LoginForm(Form):
    "Login Password form"
    email = TextField(_('Email'), [validators.Required(), validators.Email()])
    password = PasswordField(_('Password'), [validators.Required()])

    def __init__(self, *args, **kwargs):
        Form.__init__(self, *args, **kwargs)

    def validate(self):
        rv = Form.validate(self)
        if not rv:
            return False
        return True


class NewPasswordForm(Form):
    "New Password form"
    password = PasswordField(__('Password'), [validators.Required(),
        validators.EqualTo('confirm', message=_('Passwords must match'))])
    confirm = PasswordField(__('Confirm'), [validators.Required()])

    def __init__(self, *args, **kwargs):
        Form.__init__(self, *args, **kwargs)

    def validate(self):
        rv = Form.validate(self)
        if not rv:
            return False
        return True

    def reset(self):
        self.password.data = ''
        self.confirm.data = ''


class ResetPasswordForm(Form):
    "Reset Password form"
    email = TextField(_('Email'), [validators.Required(), validators.Email()])

    def __init__(self, *args, **kwargs):
        Form.__init__(self, *args, **kwargs)

    def validate(self):
        rv = Form.validate(self)
        if not rv:
            return False
        return True

    def reset(self):
        self.email.data = ''


class RegistrationForm(Form):
    "Registration form"
    vat_required = None
    if REGISTRATION_VAT:
        vat_required = [validators.Required()]

    name = TextField(__('Name'), [validators.Required()])
    email = TextField(__('Email'), [validators.Required(), validators.Email()])
    password = PasswordField(__('Password'), [validators.Required()])
    confirm = PasswordField(__('Confirm'))
    phone = TextField(__('Phone'))
    vat_country = SelectField(__('VAT Country'), choices=VAT_COUNTRIES)
    vat_number = TextField(__('VAT Number'), vat_required)

    def __init__(self, *args, **kwargs):
        Form.__init__(self, *args, **kwargs)

    def validate(self):
        rv = Form.validate(self)
        if not rv:
            return False
        return True

    def reset(self):
        self.password.data = ''
        self.confirm.data = ''
        self.vat_number.data = ''


class ActivateForm(Form):
    "Activate form"
    act_code = HiddenField(__('Activation Code'), [validators.Required()])
    email = HiddenField(__('Email'), [validators.Required(), validators.Email()])

    def __init__(self, *args, **kwargs):
        Form.__init__(self, *args, **kwargs)

    def validate(self):
        rv = Form.validate(self)
        if not rv:
            return False
        return True


def create_act_code(code_type="new"):
    """Create activation code
    A 12 character activation code indicates reset while 16
    character activation code indicates a new registration
    :param code_type: string
    return activation code
    """
    assert code_type in ("new", "reset")
    length = 16 if code_type == "new" else 12
    act_code = ''.join(random.sample(string.letters + string.digits, length))

    return act_code

def send_reset_email(user):
    """
    Send an account reset email to the user
    :param user: dict
    """
    mail = Mail(current_app)

    subject =  '%s - %s' % (current_app.config.get('TITLE'), _('Account Password Reset'))
    msg = Message(subject,
            body = render_template('emails/reset-text.jinja', user=user),
            html = render_template('emails/reset-html.jinja', user=user),
            sender = current_app.config.get('DEFAULT_MAIL_SENDER'),
            recipients = [user['email']])
    mail.send(msg)

def send_activation_email(user):
    """
    Send an new account email to the user
    :param user: dict
    """
    mail = Mail(current_app)

    subject =  '%s - %s' % (current_app.config.get('TITLE'), _('New Account Activation'))
    msg = Message(subject,
            body = render_template('emails/activation-text.jinja', user=user),
            html = render_template('emails/activation-html.jinja', user=user),
            sender = current_app.config.get('DEFAULT_MAIL_SENDER'),
            recipients = [user['email']])
    mail.send(msg)

def send_new_password(user):
    """
    Send an new password account to the user
    :param user: dict
    """
    mail = Mail(current_app)

    subject =  '%s - %s' % (current_app.config.get('TITLE'), _('New Account Password'))
    msg = Message(subject,
            body = render_template('emails/new-password-text.jinja', user=user),
            html = render_template('emails/new-password-html.jinja', user=user),
            sender = current_app.config.get('DEFAULT_MAIL_SENDER'),
            recipients = [user['email']])
    mail.send(msg)

@portal.route("/login", methods=["GET", "POST"], endpoint="login")
@tryton.transaction()
def login(lang):
    '''Login App'''
    data = {}

    if not current_app.config.get('ACTIVE_LOGIN'):
        abort(404)

    def _get_user(email):
        '''Search user by email
        :param email: string
        return user list[dict]
        '''
        fields = [
            'party',
            'display_name',
            'email',
            'password',
            'salt',
            'activation_code',
            'manager',
            ]
        if LOGIN_EXTRA_FIELDS:
            fields = fields+LOGIN_EXTRA_FIELDS
        users = GalateaUser.search_read([
            ('email', '=', email),
            ('active', '=', True),
            ('websites', 'in', [GALATEA_WEBSITE]),
            ], limit=1, fields_names=fields)
        return users

    def _validate_user(user, password):
        '''Validate user and password
        :param user: object
        :param password: string
        return Bool
        '''
        activation_code = user['activation_code']
        if activation_code and len(activation_code) == 16:
            flash(_("Your account has not been activated yet!"))
            return False

        salt = user['salt']
        if salt:
            password += salt
        if hashlib:
            digest = hashlib.sha1(password).hexdigest()
        else:
            digest = sha.new(password).hexdigest()
        if digest != user['password']:
            flash(_("The password is invalid"), "danger")
            return False

        return True

    form = LoginForm()
    if form.validate_on_submit():
        email = request.form.get('email')
        password = request.form.get('password')

        users = _get_user(email)

        if users:
            user, = users
            login = _validate_user(user, password)
            if login:
                session['logged_in'] = True
                session['user'] = user['id']
                session['display_name'] = user['display_name']
                session['customer'] = user['party']
                session['email'] = user['email']
                for field in LOGIN_EXTRA_FIELDS: # add extra fields in session
                     session[field] = user[field]
                if user['manager']:
                    session['manager'] = True
                flash(_('You are logged in'))
                slogin.send(current_app._get_current_object(),
                    user=user['id'],
                    session=session.sid,
                    website=current_app.config.get('TRYTON_GALATEA_SITE', None),
                    )
                if request.form.get('redirect'):
                    # TODO: check redirect is a rule site
                    path_redirect = request.form['redirect']
                    if not path_redirect[:4] == 'http':
                        return redirect(path_redirect)
                if REDIRECT_AFTER_LOGIN:
                    return redirect(url_for(REDIRECT_AFTER_LOGIN, lang=g.language))
                else:
                    return redirect(url_for(g.language))
        else:
            flash(_("User email don't exist or disabled user."), 'danger')

        data['email'] = email
        sfailed_login.send(form=form)

    return render_template('login.html', form=form, data=data)

@portal.route('/logout', endpoint="logout")
@login_required
@tryton.transaction()
def logout(lang):
    '''Logout App'''
    if not current_app.config.get('ACTIVE_LOGIN'):
        abort(404)

    user = session.get('user')

    # Remove all sessions
    session.pop('logged_in', None)
    session.pop('user', None)
    session.pop('display_name', None)
    session.pop('manager', None)
    session.pop('customer', None)
    session.pop('email', None)

    for field in LOGIN_EXTRA_FIELDS: # drop extra session fields
         session.pop(field, None)

    slogout.send(current_app._get_current_object(),
        user=user,
        website=current_app.config.get('TRYTON_GALATEA_SITE', None),
        )

    flash(_('You are logged out.'))
    if REDIRECT_AFTER_LOGOUT:
        return redirect(url_for(REDIRECT_AFTER_LOGOUT, lang=g.language))
    else:
        return redirect(url_for(g.language))

@portal.route('/new-password', methods=["GET", "POST"], endpoint="new-password")
@login_required
@tryton.transaction()
def new_password(lang):
    '''New Password User Account'''

    def _save_password(password):
        '''Save new password user
        :param password: string
        return user dict
        '''
        user = None
        users = GalateaUser.search([
            ('id', '=', session['user']),
            ], limit=1)
        if users:
            user, = users
            GalateaUser.write([user], {
                    'password': password,
                    })
            data = {
                'display_name': user.display_name,
                'email': user.email,
                'password': password,
                }
            return data
        return user

    form = NewPasswordForm()
    if form.validate_on_submit():
        password = request.form.get('password')
        confirm = request.form.get('confirm')

        if password == confirm and \
                len(password) >= current_app.config.get('LEN_PASSWORD', 6):
            user = _save_password(password)
            if user:
                send_new_password(user)
            flash(_('The password has been saved.'))
        else:
            flash(_("The passwords don't match or length is not valid! " \
                "Add the new password another time and save."), "danger")
        form.reset()

    return render_template('new-password.html', form=form)

@portal.route('/reset-password', methods=["GET", "POST"], endpoint="reset-password")
@tryton.transaction()
def reset_password(lang):
    '''Reset Password User Account'''
    if not current_app.config.get('ACTIVE_LOGIN'):
        abort(404)

    def _get_user(email):
        '''Search user by email
        :param email: string
        return user list[dict]
        '''
        user = None
        users = GalateaUser.search_read([
            ('email', '=', email),
            ('active', '=', True),
            ], limit=1, fields_names=[
                'display_name',
                'email',
                'password',
                'salt',
                'activation_code',
                ])
        if users:
            user, = users
        return user

    def _save_act_code(user, act_code):
        '''Write user activation code
        :param user: dict
        :param act_code: string
        '''
        user = GalateaUser(int(user['id']))
        GalateaUser.write([user], {'activation_code': act_code})

    form = ResetPasswordForm()
    if form.validate_on_submit():
        email = request.form.get('email')

        user = _get_user(email)
        if not user:
            flash(_('Not found email address.'))
            return render_template('reset-password.html', form=form)

        # save activation code
        act_code = create_act_code(code_type="reset")
        _save_act_code(user, act_code)

        # send email activation code
        user['act_code'] = act_code
        send_reset_email(user)

        flash('%s: %s' % (
            _('An email has been sent to reset your password.'),
            user['email']))
        form.reset()

    return render_template('reset-password.html', form=form)

@portal.route('/activate', methods=["GET", "POST"], endpoint="activate")
@tryton.transaction()
def activate(lang):
    '''Activate user account'''
    act_code = request.args.get('act_code')
    email = request.args.get('email')

    form = ActivateForm()
    if request.form.get('act_code'):
        act_code = request.form.get('act_code')
        email = request.form.get('email')

    def _get_user(email, act_code):
        '''Search user by email
        :param email: string
        return user list[dict]
        '''
        user = None
        users = GalateaUser.search_read([
            ('email', '=', email),
            ('active', '=', True),
            ('activation_code', '=', act_code),
            ], limit=1, fields_names=[
                'display_name',
                'email',
                'password',
                'salt',
                'activation_code',
                'party',
                'email',
                ])
        if users:
            user, = users
        return user

    def _reset_act_code(user):
        '''Add null activation code
        :param user: dict
        '''
        user = GalateaUser(int(user['id']))
        GalateaUser.write([user], {'activation_code': None})

    user = _get_user(email, act_code)

    # active new user
    if user and len(act_code) == 16:
        if request.method == 'POST':
            _reset_act_code(user) # reset activation code
            session['logged_in'] = True
            session['user'] = user['id']
            session['customer'] = user['party']
            session['email'] = user['email']
            session['display_name'] = user['display_name']
            flash(_('Your account has been activated.'))
            slogin.send(current_app._get_current_object(),
                user=user['id'],
                session=session.sid,
                website=current_app.config.get('TRYTON_GALATEA_SITE', None),
                )
        else:
            data = {
                'act_code': act_code,
                'email': email,
                }
            return render_template('activate.html', form=form, data=data)

    # active new password
    if user and len(act_code) == 12:
        session['logged_in'] = True
        session['user'] = user['id']
        session['display_name'] = user['display_name']
        flash(_('You are logged in'))
        # Not signal login because cannot execute UPDATE in a read-only transaction
        return redirect(url_for('.new-password', lang=g.language))

    return redirect('/%s/' % g.language)

@portal.route('/registration', methods=["GET", "POST"], endpoint="registration")
@tryton.transaction()
def registration(lang):
    '''Registration User Account'''
    if not current_app.config.get('ACTIVE_REGISTRATION'):
        abort(404)

    def _get_user(email):
        '''Search user by email
        :param email: string
        return user list[dict]
        '''
        user = None
        with Transaction().set_context(active_test=False):
            users = GalateaUser.search_read([
                ('email', '=', email),
                ], limit=1, fields_names=[
                    'display_name',
                    'email',
                    'password',
                    'salt',
                    'activation_code',
                    ])
        if users:
            user, = users
        return user

    def _save_user(data):
        '''Save user values
        :param data: dict
        '''
        party = None

        websites = Website.search([
            ('id', '=', GALATEA_WEBSITE),
            ], limit=1)
        if not websites:
            abort(404)
        website, = websites

        # search if email exist
        contacts = ContactMechanism.search([
            ('type', '=', 'email'),
            ('value', '=', data.get('email')),
            ], limit=1)
        if contacts:
            contact, = contacts
            party = contact.party

        eu_vat = data.get('eu_vat')
        vat_code = data.get('vat_code')

        # search if vat exist
        if REGISTRATION_VAT and eu_vat and vat_code:
            parties = Party.search([
                ('vat_code', '=', vat_code),
                ], limit=1)
            if parties:
                if REGISTRATION_VAT_CHECK_CUSTOMER:
                    flash(_('Exist a customer with your VAT. Please, ' \
                        'login or contact us to create a new user.'), "danger")
                    return
                party, = parties

        if not party:
            party_data = {
                'name': data.get('display_name'),
                'addresses': [],
                }

            # identifiers
            if REGISTRATION_VAT:
                if vat_code:
                    if eu_vat:
                        vat_party = {
                            'type': 'eu_vat',
                            'code': vat_code,
                            }
                    else:
                        vat_party = {
                            'type': None, # not eu vat
                            'code': vat_code,
                            }
                    party_data['identifiers'] = [('create', [vat_party])]

            # contact mechanisms
            contact_datas = []
            if data.get('email'):
                contact_datas.append({
                    'type': 'email',
                    'value': data['email'],
                    })
            if data.get('phone'):
                contact_datas.append({
                    'type': 'phone',
                    'value': data['phone'],
                    })
            party_data['contact_mechanisms'] = [('create', contact_datas)]

            # save party
            party, = Party.create([party_data])

        del data['eu_vat']
        del data['vat_code']
        if data.get('phone'):
            del data['phone']

        data['company'] = website.company.id
        data['party'] = party.id
        user_ids = GalateaUser.create([data])
        return user_ids

    form = RegistrationForm()
    if form.validate_on_submit():
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm = request.form.get('confirm')
        phone = request.form.get('phone')
        vat_country = request.form.get('vat_country')
        vat_number = request.form.get('vat_number')

        if not (password == confirm and \
                len(password) >= current_app.config.get('LEN_PASSWORD', 6)):
            flash(_("Password don't match or length not valid! " \
                "Repeat add new password and save"), "danger")
            form.reset()
            return render_template('registration.html', form=form)

        user = _get_user(email)
        if user:
            flash(_('Email address already exists. Do you forget the password?'))
            return render_template('registration.html', form=form)

        eu_vat = False
        if REGISTRATION_VAT:
            if vat_country:
                eu_vat = True
                vat_code = '%s%s' % (vat_country.upper(), vat_number)
                vat_code = vat.compact(vat_code)
                if not vat.is_valid(vat_code):
                    flash(_('Vat number is not valid.'), 'danger')
                    return render_template('registration.html', form=form)
            elif vat_number:
                vat_code = '%s' % vat_number
            else:
                vat_code = None

        act_code = create_act_code(code_type="new")

        # save new account - user
        data = {
            'display_name': name,
            'email': email,
            'phone': phone,
            'password': password,
            'activation_code': act_code,
            'eu_vat': eu_vat,
            'vat_code': vat_code,
            }
        user_ids = _save_user(data)
        if user_ids:
            # send email activation account
            send_activation_email(data)

            flash('%s: %s' % (
                _('An email has been sent to activate your account.'),
                email))
            form.reset()

    form.vat_country.data = DEFAULT_COUNTRY.upper() or ''
    return render_template('registration.html', form=form)

@portal.route('/subdivisions', methods=['GET'], endpoint="subdivisions")
@tryton.transaction()
def subdivisions(lang):
    '''Return all subdivisions by country (Json)'''
    country = int(request.args.get('country', 0))
    subdivisions = Subdivision.search([('country', '=', country)])

    return jsonify(
        result=[{
            'id': s.id,
            'name': s.name,
            'code': s.code,
            } for s in subdivisions
            ]
        )

@portal.route('/json/search', methods=['GET'], endpoint="jsonsearch")
@manager_required
@tryton.transaction()
def jsonsearch(lang):
    '''Search rec_name in model (Json)

    Example:
    /json/search?model=party.party&query=%QUERY
    '''
    model = request.args.get('model')
    query = request.args.get('query')

    if not model:
        return jsonify(result=[])

    Model = tryton.pool.get(model)
    rows = Model.search_read([
        ('rec_name', 'ilike', '%'+query+'%'),
        ], fields_names=['name'])

    return jsonify(results=rows)

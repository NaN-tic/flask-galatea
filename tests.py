#!/usr/bin/env python
from flask import url_for
from flask_tryton import Tryton

def test_galatea(self):
    '''Test Galatea (registration, activate, login, reset password)'''
    tryton = Tryton(self.app)

    @tryton.default_context
    def default_context():
        context = {}
        context['website'] = self.app.config.get('TRYTON_GALATEA_SITE')
        context['company'] = self.app.config.get('TRYTON_COMPANY')
        context['shop'] = self.app.config.get('TRYTON_SALE_SHOP')
        context['shops'] = self.app.config.get('TRYTON_SALE_SHOPS')
        context['locations'] = self.app.config.get('TRYTON_LOCATIONS')
        return context

    # registration
    response = self.client.post(url_for('portal.registration', lang=self.language), data=dict(
        name = self.email.split('@')[0],
        invoice_name= self.email.split('@')[0],
        email = self.email,
        password = self.password,
        confirm = self.password,
        phone = '938902108',
        vat_country = 'es',
        vat_number = self.vat_number,
        ), follow_redirects=True)
    assert 'An email has been sent to activate your account' in str(response.data)

    # activate
    @tryton.transaction()
    def get_activation_code(email):
        GalateaUser = tryton.pool.get('galatea.user')

        user, = GalateaUser.search([
            ('email', '=', email),
            ], limit=1)
        return user.activation_code

    activation_code = get_activation_code(self.email)
    response = self.client.post(url_for('portal.activate', lang=self.language), data=dict(
        act_code = activation_code,
        email = self.email,
        ), follow_redirects=True)
    assert 'Your account has been activated' in str(response.data)


def test_reset_password(self):
    '''Test Reset Password Portal Galatea'''
    # reset password
    response = self.client.post(url_for('portal.reset-password', lang=self.language), data=dict(
        email = self.email,
        ), follow_redirects=True)
    assert 'An email has been sent to reset your password' in str(response.data)

    tryton = Tryton(self.app)

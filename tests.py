#!/usr/bin/env python
from flask import url_for
from flask_tryton import Tryton

def test_registration(self):
    '''Test Registration Portal Galatea'''
    tryton = Tryton(self.app)

    # registration
    response = self.client.post(url_for('portal.registration', lang=self.language),
        data=dict(
            name = self.email.split('@')[0],
            email = self.email,
            password = self.password,
            confirm = self.password,
            phone = '938902108',
            vat_country = 'es',
            vat_number = self.vat_number,
        ), follow_redirects=True)
    assert 'An email has been sent to activate your account' in response.data

    # activate
    @tryton.transaction()
    def get_activation_code(email):
        GalateaUser = tryton.pool.get('galatea.user')

        user, = GalateaUser.search([
            ('email', '=', email),
            ], limit=1)
        return user.activation_code

    activation_code = get_activation_code(self.email)
    response = self.client.post(url_for('portal.activate', lang=self.language),
        data=dict(
            act_code = activation_code,
            email = self.email,
        ), follow_redirects=True)
    assert 'Your account has been activated' in response.data

def test_login(self):
    '''Test Login Portal Galatea'''
    # login
    response = self.client.post(url_for('portal.login', lang=self.language),
        data=dict(
            email = self.email,
            password = self.password,
        ), follow_redirects=True)
    assert 'You are logged in' in response.data

    # reset password
    response = self.client.post(url_for('portal.reset-password', lang=self.language),
        data=dict(
            email = self.email,
        ), follow_redirects=True)
    assert 'An email has been sent to reset your password' in response.data

def test_logout(self):
    '''Test Logout Portal Galatea'''
    # logout
    response = self.client.get(url_for('portal.logout', lang=self.language),
        follow_redirects=True)
    assert 'You are logged out' in response.data

# The COPYRIGHT file at the top level of this repository contains the full
# copyright notices and license terms.
from flask import Blueprint, render_template, current_app, redirect, abort
from trytond.transaction import Transaction

from .tryton import tryton


GALATEA_WEBSITE = current_app.config.get('TRYTON_GALATEA_SITE')

galatea = Blueprint('galatea', __name__, template_folder='templates')

Article = tryton.pool.get('galatea.cms.article')
Uri = tryton.pool.get('galatea.uri')


@galatea.route("/<path:uri_str>", endpoint="uri")
@tryton.transaction()
def uri(uri_str):
    '''Process URI'''
    uri_str = uri_str[:-1] if uri_str and uri_str[-1] == '/' else uri_str

    with Transaction().set_context(website=GALATEA_WEBSITE):
        uris = Uri.search([
            ('uri', '=', uri_str),
            ('active', '=', True),
            ('website', '=', GALATEA_WEBSITE),
            ])
    if not uris:
        abort(404)

    uri = uris[0]
    if uri.type in ('internal_redirection', 'external_redirection'):
        target = (uri.internal_redirection.uri
            if uri.type == 'internal_redirection' else uri.external_url)
        return redirect(target, code=uri.redirection_code)

    return render_template(uri.template.filename, uri=uri)

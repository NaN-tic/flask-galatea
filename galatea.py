# The COPYRIGHT file at the top level of this repository contains the full
# copyright notices and license terms.
from flask import (Blueprint, render_template, current_app, redirect, abort,
session, request)
from trytond.transaction import Transaction
from .tryton import tryton
from .helpers import cache

GALATEA_WEBSITE = current_app.config.get('TRYTON_GALATEA_SITE')
COMPUTE_CACHE_KEY = None

galatea = Blueprint('galatea', __name__, template_folder='templates')

Uri = tryton.pool.get('galatea.uri')

def set_compute_cache_key(cache_key):
    global COMPUTE_CACHE_KEY
    COMPUTE_CACHE_KEY = cache_key

@galatea.route("/<path:uri_str>", endpoint="uri")
@tryton.transaction()
def uri(uri_str):
    '''Process URI'''
    uri_str = uri_str[:-1] if uri_str and uri_str[-1] == '/' else uri_str

    use_cache = request.args.get('use_cache', '')
    use_cache = use_cache.lower() not in ('false', '0')
    if use_cache:
        if COMPUTE_CACHE_KEY:
            cache_key = COMPUTE_CACHE_KEY(uri_str)
        else:
            cache_key = uri_str
        res = cache.get(cache_key)
        if res is not None:
            return res


    with Transaction().set_context(website=GALATEA_WEBSITE):
        uris = Uri.search([
            ('uri', '=', uri_str),
            ('active', '=', True),
            ('website', '=', GALATEA_WEBSITE),
            ('anchor', '=', False),
            ], limit=1)
        if uris:
            uri, = uris
            res = uri_aux(uri)
            if use_cache:
                cache.set(cache_key, res, timeout=300)
            return res

        abort(404)

def uri_aux(uri):
    if uri.type in ('internal_redirection', 'external_redirection'):
        target = (uri.internal_redirection.uri
            if uri.type == 'internal_redirection' else uri.external_redirection)
        return redirect(target, code=int(uri.redirection_code))
    elif (uri.type == 'content' and uri.template.allowed_models and not uri.content):
        abort(404)
    elif (uri.type == 'clear-cache'):
        current_app.cache.clear()
        return redirect("/", code=303)
    session['next'] = uri.uri
    return render_template(uri.template.filename, uri=uri)

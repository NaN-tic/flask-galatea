#This file is part galatea blueprint for Flask.
#The COPYRIGHT file at the top level of this repository contains
#the full copyright notices and license terms.
from flask import redirect, url_for, session,  request, current_app, abort
from functools import wraps

def secure(function):
    @wraps(function)
    def decorated_function(*args, **kwargs):
        if not request.is_secure:
            return redirect(request.url.replace('http://', 'https://'))
        else:
            return function(*args, **kwargs)
    return decorated_function

def customer_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        customer = session.get('customer', None)
        if not customer:
            return redirect('%s?redirect=%s' % (url_for('portal.logout', lang='es'), request.path))
        return f(*args, **kwargs)
    return decorated_function

def manager_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        manager = session.get('manager', None)
        if not manager:
            abort(404)
        return f(*args, **kwargs)
    return decorated_function

def get_cache():
    """Retorna la instància de cache configurada a current_app, si existeix."""
    return getattr(current_app, "cache", None)

def cached(timeout=5 * 60, key="view/%s"):
    """Decorator per cachejar la sortida d'una vista Flask."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            cache = get_cache()
            if cache:
                cache_key = key
                rv = cache.get(cache_key)
                if rv is not None:
                    return rv
                rv = f(*args, **kwargs)
                cache.set(cache_key, rv, timeout=timeout)
                return rv
            return f(*args, **kwargs)
        return decorated_function
    return decorator
#This file is part galatea blueprint for Flask.
#The COPYRIGHT file at the top level of this repository contains
#the full copyright notices and license terms.
from flask import request
from flask.sessions import SessionInterface, SessionMixin
from secure_cookie.sessions import Session as SessionBase, SessionStore
from flask.globals import current_app

# Deprecated session from werkzeug
# https://werkzeug.palletsprojects.com/en/0.15.x/contrib/sessions/
# https://github.com/pallets/secure-cookie


class Session(SessionBase, SessionMixin):
    "Default Session Object"


class NullSession(Session):
    """
    Class used to generate nicer error messages if sessions are not
    available.  Will still allow read-only access to the empty session
    but fail on setting.
    """

    def _fail(self, *args, **kwargs):
        raise RuntimeError('the session is unavailable because no secret '
                           'key was set.  Set the secret_key on the '
                           'application to something unique and secret.')
    __setitem__ = __delitem__ = clear = pop = popitem = \
        update = setdefault = _fail
    del _fail


class GalateaSessionStore(SessionStore):
    """
    Session store

    :param session_class: The session class to use.
    Defaults to :class:`Session`.
    """
    def __init__(self, session_class=Session):
        SessionStore.__init__(self, session_class)

    def save(self, session):
        """
        Updates the session
        """
        current_app.cache.set(
            session.sid, dict(session), 30 * 24 * 60 * 60
        )

    def delete(self, session):
        """
        Deletes the session
        """
        current_app.cache.delete(session.sid)

    def get(self, sid):
        """
        Returns session
        """
        if not self.is_valid_key(sid):
            return self.new()
        session_data = current_app.cache.get(sid)
        if session_data is None:
            session_data = {}
        return self.session_class(session_data, sid, False)

    def list(self):
        """
        Lists all sessions
        """
        raise Exception("Not implemented yet")


class GalateaSessionInterface(SessionInterface):
    """Session Management Class"""

    session_store = GalateaSessionStore()
    null_session_class = NullSession

    def open_session(self, app, request):
        """
        Creates or opens a new session.

        :param request: an instance of :attr:`request_class`.
        """
        sid = request.cookies.get(app.session_cookie_name, None)
        if sid:
            return self.session_store.get(sid)
        else:
            return self.session_store.new()

    def save_session(self, app, session, response):
        """
        Saves the session if it needs updates.  For the default
        implementation, check :meth:`open_session`.

        :param session: the session to be saved
        :param response: an instance of :attr:`response_class`
        """
        #~ if session.should_save:
        self.session_store.save(session)
        expires = self.get_expiration_time(app, session)
        domain = self.get_cookie_domain(app)

        sid = request.cookies.get(app.session_cookie_name, None)
        if session.sid != sid:
            # The only information in the session is the sid, and the
            # only reason why a cookie should be set again is if that
            # has changed
            response.set_cookie(
                app.session_cookie_name, session.sid,
                expires=expires, httponly=False, domain=domain
            )

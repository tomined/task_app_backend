from flask import session
from datetime import timedelta


def set_session_expiration(app):
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=30)
    return app.permanent_session_lifetime
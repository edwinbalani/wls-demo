import datetime
import os
import re

from urllib.parse import urlsplit

from flask import Flask, Blueprint, request, session, render_template, redirect, abort, url_for, flash

from ucam_wls import LoginService, AuthPrincipal, AuthRequest, load_private_key
from ucam_wls.errors import InvalidAuthRequest, ProtocolVersionUnsupported, NoMutualAuthType
from ucam_wls.status import (
        WAA_NOT_AUTHORISED,
        INTERACTION_REQUIRED,
        NO_MUTUAL_AUTH_TYPES,
        UNSUPPORTED_PROTO_VER,
        REQUEST_PARAM_ERROR,
        USER_CANCEL,
)
from ucam_wls.util import datetime_to_protocol

app = Flask(__name__)

class BaseConfig:
    DEBUG = False
    TESTING = False
    WLS_KEYS = {}
    ALLOW_INSECURE_WAA = False
    BANNED_WAA_DOMAINS = []
    WLS_TITLE = 'Web login service'
    WLS_BRAND_HTML = WLS_TITLE

class SecurityConfig:
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = True

app.config.from_object(BaseConfig)
if 'WLS_SETTINGS' in os.environ:
    app.config.from_envvar('WLS_SETTINGS')
app.config.from_object(SecurityConfig)

if app.config['TESTING']:
    app.config['WLS_KEYS'].setdefault(
        901,
        load_private_key(path=os.path.join(os.path.dirname(__file__), 'keys', '901.pem'), kid=901),
    )
    WLS_KEY = app.config['WLS_KEYS'][901]
    app.config.setdefault('SECRET_KEY', os.urandom(32))
else:
    WLS_KEY = app.config['WLS_KEYS'][app.config['WLS_USE_KEY']]

wls = LoginService(key=WLS_KEY, auth_methods=['pwd'])

@app.route('/')
def index():
    return render_template('index.html')

def check_credentials(username, password):
    if app.config['TESTING']:
        return re.match(r'^test0(00[1-9]|0[1-9][0-9]|[1-4][0-9][0-9]|500)$', username) and password == 'test'
    else:
        pass # TODO

@app.route('/logout')
def logout():
    for k in ('userid', 'expiry'):
        if k in session:
            del session[k]
    flash("Logged out successfully.", category="success")
    return redirect(url_for('index'))

@app.route('/test')
def wls_test_menu():
    now = datetime.datetime.utcnow()
    future_time = now + datetime.timedelta(seconds=300)
    far_off_future = now + datetime.timedelta(days=3650)
    past = now + datetime.timedelta(days=-3650)

    for t in (now, future_time, far_off_future, past):
        t = datetime_to_protocol(t)

    ctx = dict(now=now, future_time=future_time, far_off_future=far_off_future, past=past)

    return render_template('test.html', **ctx)

def wls_fail(message):
    return render_template('error.html', message=message, fail=True), 400

def construct_principal(userid, expiry):
    principal = AuthPrincipal(userid=userid, auth_methods=['pwd'],
                                session_expiry=expiry)
    if app.config['TESTING']:
        if int(principal.userid[4:]) in range(400):
            principal.ptags = ['current']
        elif int(principal.userid[4:]) in range(400, 450):
            principal.ptags = ['current', 'x-admin']

    return principal

@app.route('/wls/authenticate', methods=['GET', 'POST'])
def authenticate():
    now = datetime.datetime.utcnow()

    try:
        wls_req = AuthRequest.from_query_string(request.query_string.decode())
    except InvalidAuthRequest as e:
        return wls_fail(message=e)
    except ProtocolVersionUnsupported as e:
        return wls_fail("The protocol version in use is not supported by this service")

    if not wls.have_mutual_auth_type(wls_req):
        if wls_req.fail:
            return wls_fail("None of the requested authentication types are supported by this service")
        else:
            wls_resp = wls.generate_failure(NO_MUTUAL_AUTH_TYPES, wls_req)
            return redirect(wls_resp.redirect_url)

    parts = urlsplit(wls_req.url)
    scheme = parts.scheme
    domain = parts.netloc

    if not domain:
        return render_template('error.html', message="No return domain specified", fail=False), 400

    ctx = {
        'wls_req': wls_req,
        'domain': domain,
    }

    if wls_req.desc:
        ctx['desc_safe'] = wls_req.desc.replace('<', '&lt;').replace('>', '&gt;')
    if wls_req.msg:
        ctx['msg_safe'] = wls_req.msg.replace('<', '&lt;').replace('>', '&gt;')

    if parts.scheme != 'https' and not app.config['ALLOW_INSECURE_WAA'] \
        and domain != 'localhost':
        ctx['scheme'] = scheme
        return render_template('insecure_waa.html', **ctx), 400

    if parts.netloc in app.config['BANNED_WAA_DOMAINS']:
        message = "Domain %s has been banned from using the login service" % parts.netloc
        if wls_req.fail:
            return wls_fail(message)
        else:
            wls_resp = wls.generate_failure(WAA_NOT_AUTHORISED, wls_req,
                msg=message,
                sign=False,
            )
            return redirect(wls_resp.redirect_url)

    if request.method == 'POST':
        username = request.form.get('userid').strip().lower() or None
        password = request.form.get('pwd') or None
        action = request.form.get('action') or None

        if action == 'cancel':
            if wls_req.fail:
                return wls_fail("The user cancelled authentication.")
            else:
                wls_resp = wls.generate_failure(USER_CANCEL, wls_req)
                return redirect(wls_resp.redirect_url)

        if not (username and password):
            err_msg = 'Missing username and/or password'
            ctx.update({
                'username': username,
                'err_msg': err_msg,
            })
            return render_template('authenticate.html', **ctx)

        if check_credentials(username, password):
            session['userid'] = username
            expiry = session['expiry'] = now + datetime.timedelta(hours=6)
            principal = construct_principal(username, expiry)
            wls_resp = wls.authenticate_active(wls_req, principal, 'pwd')
            return redirect(wls_resp.redirect_url)
        else:
            err_msg = "Unrecognised username or password"
            ctx.update({
                'username': username,
                'err_msg': err_msg,
            })
            return render_template('authenticate.html', **ctx)

    else:  # => request is GET
        saved_userid = session.get('userid')
        expiry = None
        expired = None

        if saved_userid:
            expiry = session.get('expiry')
            expired = expiry and (expiry < now)

        if saved_userid and not expired:
            # Previous session exists and hasn't expired
            if wls_req.iact is True:
                # Require re-authentication, force same userid
                ctx.update({
                    'session_existed': False,
                    'force_userid': saved_userid,
                })
                return render_template('authenticate.html', **ctx)
            else:
                # Passive authentication is possible and permissible
                principal = construct_principal(saved_userid, expiry)
                wls_resp = wls.authenticate_passive(wls_req, principal)
                return redirect(wls_resp.redirect_url)

        else:
            # Previous session has expired, or no session existed
            session_existed = (expiry is not None)

            if wls_req.iact is False:
                # We cannot authenticate passively but it is demanded, so return a failure
                if wls_req.fail:
                    return wls_fail("User interaction would be required for authentication, "
                        "but the web application demanded that authentication is completed "
                        "without it")
                else:
                    wls_resp = wls.generate_failure(INTERACTION_REQUIRED, wls_req)
                    return redirect(wls_resp.redirect_url)

            ctx.update({
                'session_existed': session_existed,
            })
            return render_template('authenticate.html', **ctx)

if __name__ == '__main__':
    app.run()

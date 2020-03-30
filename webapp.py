#!/usr/bin/env python2.7

import cgi
from datetime import datetime, timedelta
from functools import wraps
import json
import urllib
import uuid
import webapp2
from google.appengine.ext import ndb
from pybcrypt import bcrypt
from google.appengine.api import urlfetch   #need valid+certificate=True to fetch
import os
import jinja2

state = str(uuid.uuid4())
nonce = str(uuid.uuid4())


class Secret(ndb.Model):
  name = ndb.StringProperty()
  value = ndb.StringProperty()

class ModelEvent(ndb.Model):
    name = ndb.StringProperty()
    date = ndb.StringProperty()

class ModelUser(ndb.Model):
    username = ndb.StringProperty()
    pwhash = ndb.StringProperty()

    @classmethod
    def keyfor(cls, username):
        return ndb.Key(cls, username)

class ModelSession(ndb.Model):
    token = ndb.StringProperty()
    username = ndb.StringProperty()
    expires = ndb.DateTimeProperty()

    @classmethod
    def keyfor(cls, id):
        return ndb.Key(cls, id)


def session_failure(resp, message, json=False):
    """Writes a session failure to the given response.

    Args:
        resp: The webapp2.Response object.
        message: The message to send when directing to a login.
        json: If True, will send a JSON object with "login_url" and "message" fields.
            Otherwise, will send a 302 redirect to the login page.

    Returns:
        None. Can be used to error out and simultaneously exit a function, e.g.,
        by saying

            return session_failure(self.response, "no session")
    """
    if json:
        self.response.write(json.dumps({
            "login_url": "/login",
            "error": message,
        }))
        return

    params = urllib.urlencode({
        "error": message,
    })
    resp.location = "/login?" + params
    resp.status_int = 302


def require_session(json=False):
    """Returns a decorator for handler methods that require a session.

    The wrapped function will have a new parameter after "self", which
    will contain the user. All other parameters thereafter will be the same.

    Args:
        json: If True, will return JSON with "login_url" and "message" fields set.
            Otherwise will simply redirect to /login.
    """
    def require_session_impl(f):
        @wraps(f)
        def session_wrapper(self, *args, **kargs):
            tok = self.request.cookies.get('s')
            if not tok:
                return session_failure(self.response, "Not logged in.", json)

            sess_key = ModelSession.keyfor(tok)
            sess = sess_key.get()
            if not sess:
                return session_failure(self.response, "Not logged in.", json)
            elif sess.expires < datetime.now():
                sess_key.delete()
                return session_failure(self.response, "Session expired.", json)

            user = ModelUser.keyfor(sess.username).get()
            if not user:
                sess_key.delete()
                return session_failure(self.response, "No session for user.", json)

            # Found the user - pass into a keyword param.
            return f(self, user, *args, **kargs)
        return session_wrapper
    return require_session_impl


class ListEvents(webapp2.RequestHandler):
    @require_session(json=True)
    def get(self, user):
        self.response.write(json.dumps({
            'events': [dict(name=val.name, date=val.date, id=val.key.urlsafe())
                       for val in ModelEvent.query(ancestor=user.key).iter()],
            'error': None,
        }))

class DeleteEvent(webapp2.RequestHandler):
    @require_session(json=True)
    def delete(self, user, id):
        k = ndb.Key(urlsafe=id)
        k.delete()

class PostEvent(webapp2.RequestHandler):
    @require_session(json=True)
    def post(self, user):
        data = json.loads(self.request.body)
        ev = ModelEvent(parent=user.key, name=data["name"], date=data["date"])
        ev.put()

class Home(webapp2.RequestHandler):
    @require_session()
    def get(self, unused_user):
        #self.response.write(ndb.Key(Secret, "oidc_client").get().value)
        #self.response.write(state)
        google = {
            'state': state,
            'nonce': nonce,
        }
        #self.response.out.write(template.render(google))
        self.response.write(open("index.html").read())
        #self.response.write(nonce)


def create_session(resp, username, ttl=timedelta(hours=1)):
    tok = str(uuid.uuid4())
    exp = datetime.now() + ttl

    ModelSession(key=ModelSession.keyfor(tok),
                 token=tok,
                 username=username,
                 expires=exp).put()
    resp.set_cookie('s', tok, expires=exp)
    return tok


class Logout(webapp2.RequestHandler):
    @require_session()
    def get(self, unused_user):
        tok = self.request.cookies.get('s')
        if tok:
            ModelSession.keyfor(tok).delete()
            self.response.delete_cookie('s')
        self.redirect('/login')


class Login(webapp2.RequestHandler):
    def get(self):
        #self.response.write(json.dumps(state))
        google = {
            'state': state,
            'nonce': nonce,
        }
        #self.response.out.write(render(google))
        self.response.write(open("login.html").read())

    def post(self):
        # If there was already a session, delete it.
        # But wait until there's an error to delete the cookie.
        # We might just want to reset it.

        old_token = self.request.cookies.get('s')
        if old_token:
            ModelSession.keyfor(old_token).delete()

        # Check the username and password.
        username = self.request.params['username']
        password = self.request.params['password']

        user = ModelUser.keyfor(username).get()

        # Failure: back to login with error message.
        if not user or user.pwhash != bcrypt.hashpw(password, user.pwhash):
            self.response.delete_cookie('s')
            params = urllib.urlencode({
                "error": "User '{}' or password incorrect".format(cgi.escape(username)),
            })
            self.redirect("/login?" + params)
            return

        create_session(self.response, username)
        self.redirect('/')


class Register(webapp2.RequestHandler):
    def get(self):
        self.response.write(open("register.html").read())

    def post(self):
        username = self.request.params['username']
        password = self.request.params['password']
        user = ModelUser.keyfor(username).get()
        if user:
            params = urllib.urlencode({
                "error": "user {} exists".format(cgi.escape(username))
            })
            self.redirect("/register?" + params)
            return

        user = ModelUser(key=ModelUser.keyfor(username),
                         username=username,
                         pwhash=bcrypt.hashpw(password, bcrypt.gensalt(5)))
        user.put()
        create_session(self.response, username)
        self.redirect('/')


class Init(webapp2.RequestHandler):
  @ndb.transactional
  def get(self):
    key = ndb.Key(Secret, "oidc_client")
    if not key.get():
      Secret(key=key, name=key.id(), value="").put()
      return self.response.write("Success")
    return self.response.write("Already exists")

class Oidcauth(webapp2.RequestHandler):
    def get(self):
        self.redirect('/google')
        #url = 'https://www.googleapis.com/oauth2/v4/token'
        #result = urlfetch.fetch(
        #    url='https://www.googleapis.com/oauth2/v4/token',
        #    payload=urllib.urlencode({code,client_id,client_secret,grant_type="authorization_code"}),
        #    method=urlfecth.POST,
        #    validate_certificate=True)
        #I am unable to get the JWT response back.
        #url = 'https://accounts.google.com/.well-known/openid-configuration'
        #result = urlfetch.fetch(url)
        #self.response.write("result")
        #self.response.write(result.content)
        #self.response.write(self.request.params['nonce'])
    #    self.response.write(' state  ')
    #    self.response.write(state)
    #    self.response.write('')
    #    if ($request->get('odic_state') != ($app['session']->get('state'))) {
    #    return new
    #    Response('Invalid state parameter', 401);
    #    }
    #def post(self):
     #   self.redirect('/google')


class Csrf(webapp2.RequestHandler):
    def get(self):
        self.response.write(json.dumps({
            'state': state,
            'nonce': nonce,
        }))
        self.response.write(json.dumps({
            'csrf': [dict(state=state, nonce=nonce)],
            'error': None,
        }))

class Google(webapp2.RequestHandler):
    def get(self):
        username='appget'
        user = ModelUser(key=ModelUser.keyfor(username),
                         username=username,
                         pwhash=username)
        user.put()
        create_session(self.response, username)
        self.redirect('/')

app = webapp2.WSGIApplication([
    ('/events', ListEvents),
    ('/event/(.*)', DeleteEvent),
    ('/event', PostEvent),
    ('/login', Login),
    ('/logout', Logout),
    ('/register', Register),
    ('/init', Init),
    ('/(?:index.html)?', Home),
    ('/oidcauth', Oidcauth),
    ('/csrf', Csrf),
    ('/google', Google),
], debug=True)

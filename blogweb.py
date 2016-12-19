import os

import re
from string import letters

import jinja2
import webapp2
import string
import re
import random

from google.appengine.ext import db

import hashlib
import hmac

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)


SECRET_key = open("/home/bittu/Documents/github/multiuserblog/key/key.txt")
SECRET = SECRET_key.read().split()[0]
def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
    a= h.split("|")[0]
    if (h==make_secure_val(a)):
        return a

COOKIE_RE = re.compile(r'.+=;\s*Path=/')
def valid_cookie(cookie):
    return cookie and COOKIE_RE.match(cookie)


def make_salt():
    return "".join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name+pw+salt).hexdigest()
    return "%s,%s" % (h, salt)

def valid_pw(name, pw, h):
    salt=h.split(",")[1]
    return h == make_pw_hash(name, pw, salt)


def user_key(group = 'default'):
    return db.Key.from_path('users', group)

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

class Userinfo(db.Model):
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True) # not regular password but hash of the password
    email = db.EmailProperty()

    # if you want to work on above created class instead of creating instances, we can use this method
    # @classmethod is called decorator
    @classmethod
    def by_id(cls, uid):
        return Userinfo.get_by_id(uid, parent = user_key())

    @classmethod
    def by_name(cls, username):
        u = Userinfo.all().filter('username =', username).get()
        return u

    @classmethod
    def register(cls, username, password, email =None):
        pw_hash = make_pw_hash(username, password)
        return Userinfo(parent = user_key(),
                        username = username,
                        password = pw_hash,
                        email = email)

    @classmethod
    def login(cls, username, password):
        u = cls.by_name(username)
        if u and valid_pw(username, password, u.password):
            return u

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

class Post(db.Model):
    userid = db.IntegerProperty(required=True)
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return self._render_text
        # return render_str("post.html", p = self)

    def getUName(self):
        user = Userinfo.by_id(self.userid)
        return user.username


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.write(*a,**kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def setting_cookies(self, name, val):
        new_cookie_val = make_secure_val(val)
        self.response.headers.add_header('Set-Cookie', '%s=%s; path=/' % (name, new_cookie_val))

    def reading_cookies(self,name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.setting_cookies('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; path=/')

## This methods gets executed for each page and
# verfies user login status, using oookie information.
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.reading_cookies('user_id')
        self.user = uid and Userinfo.by_id(int(uid))


class SignUp(Handler):
    def get(self):
        self.render("signup.html")

    def post(self):
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        params = dict(username = username,
                      email = email)

        if not valid_username(username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(password):
            params['error_passwordord'] = "That wasn't a valid passwordord."
            have_error = True
        elif (password != verify):
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup.html', **params)
        else:
            ## add cookies
            check_user_exist = Userinfo.by_name(username)
            if check_user_exist:
                self.render('signup.html', error_username = "That user already exists")
            else:
                uinfo = Userinfo.register(username, password , email)
                uinfo.put()

                self.login(uinfo)
                self.render('profile.html',username=username)


class Front(Handler):
    def get(self):
        self.render('firstpage.html')


class LogIn(Handler):
    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u=Userinfo.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            self.render('login.html',error_username="username does not exist")


class LogOut(Handler):
    def get(self):
        self.logout()
        self.redirect('/login')


class Profile(Handler):
    def get(self):
        #username =
        user_id = self.user.key().id()
        user_name = user_id and Userinfo.by_id(int(user_id))
        if user_name:
            self.render("profile.html",username=user_id)
        else:
            self.redirect('/signup')

class BlogFront(Handler):
    def get(self):
        posts = db.GqlQuery("select * from Post order by created desc limit 10")
        self.render('bloghome.html', posts = posts)

class PostPage(Handler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("blogpage.html", post = post)

class NewPost(Handler):
    def get(self):
        if self.user:
            self.render('blognew.html')
        else:
            self.render('login.html')

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent = blog_key(), userid=self.user.key().id(), subject = subject, content = content)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("blognew.html", subject=subject, content=content, error=error)


app = webapp2.WSGIApplication([('/?', Front),
                               ('/signup', SignUp),
                               ('/login', LogIn),
                               ('/logout', LogOut),
                               ('/profile/?',Profile),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),],
                              debug=True)


## to delete all data from database
# dev_appserver.py --clear_datastore=yes /home/bittu/Documents/github/Udacity/multiuserblog/project/subproject/

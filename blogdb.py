from google.appengine.ext import db
from blogweb import *

import hashlib
import hmac


# SECRET_key = open("/home/bittu/Documents/github/multiuserblog/key/key.txt")
# SECRET = SECRET_key.read().split()[0]
# do not share this. This is open for only learning purposes
SECRET = "thisissecretcode"

# hashing cookies and password


def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()


def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))


def check_secure_val(h):
    a = h.split("|")[0]
    if (h == make_secure_val(a)):
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
    salt = h.split(",")[1]
    return h == make_pw_hash(name, pw, salt)


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def user_key(group='default'):
    return db.Key.from_path('users', group)


class Userinfo(db.Model):
    username = db.StringProperty(required=True)
    password = db.StringProperty(required=True)
    # not regular password but hash of the password
    email = db.StringProperty()

    # if you want to work on above created class instead of creating instances,
    # we can use this method
    # @classmethod is called decorator
    @classmethod
    def by_id(cls, uid):
        return Userinfo.get_by_id(uid, parent=user_key())

    @classmethod
    def by_name(cls, username):
        u = Userinfo.all().filter('username =', username).get()
        return u

    @classmethod
    def register(cls, username, password, email=None):
        pw_hash = make_pw_hash(username, password)
        return Userinfo(parent=user_key(),
                        username=username,
                        password=pw_hash,
                        email=email)

    @classmethod
    def login(cls, username, password):
        u = cls.by_name(username)
        if u:
            if valid_pw(username, password, u.password):
                return u
            else:
                return "wrong password"

# need to read more about this


def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


class Post(db.Model):
    userid = db.IntegerProperty(required=True)
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return self._render_text
        # return render_str("post.html", p = self)

    def getUName(self):
        user = Userinfo.by_id(self.userid)
        return user.username


class Comment(db.Model):
    userid = db.IntegerProperty(required=True)
    postid = db.IntegerProperty(required=True)
    comment = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    def getUName(self):
        user = Userinfo.by_id(self.userid)
        return user.username


class Like(db.Model):
    userid = db.IntegerProperty(required=True)
    postid = db.IntegerProperty(required=True)

    def getUName(self):
        user = Userinfo.by_id(self.userid)
        return user.username

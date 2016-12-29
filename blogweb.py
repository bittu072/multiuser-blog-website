import os

import re
from string import letters

import jinja2
import webapp2
import string
import random

from google.appengine.ext import db

import hashlib
import hmac

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)


EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)


# SECRET_key = open("/home/bittu/Documents/github/multiuserblog/key/key.txt")
# SECRET = SECRET_key.read().split()[0]
SECRET = "thisissecretcode"


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


def user_key(group='default'):
    return db.Key.from_path('users', group)


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


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


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def setting_cookies(self, name, val):
        new_cookie_val = make_secure_val(val)
        self.response.headers.add_header('Set-Cookie',
                                         '%s=%s; path=/' %
                                         (name, new_cookie_val))

    def reading_cookies(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.setting_cookies('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; path=/')

# This methods gets executed for each page and
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

        params = dict(username=username,
                      email=email)

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
            # add cookies
            check_user_exist = Userinfo.by_name(username)
            if check_user_exist:
                self.render('signup.html',
                            error_username="That user already exists")
            else:
                uinfo = Userinfo.register(username, password, email)
                uinfo.put()

                self.login(uinfo)
                self.render('profile.html', username=username)


class Front(Handler):
    def get(self):
        self.render('firstpage.html')


class LogIn(Handler):
    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = Userinfo.login(username, password)
        if u:
            if u == "wrong password":
                self.render('login.html', error_password="wrong password")
            else:
                self.login(u)
                self.redirect('/profile')
        else:
            self.render('login.html', error_username="username does not exist")


class LogOut(Handler):
    def get(self):
        self.logout()
        self.redirect('/login')


class Profile(Handler):
    def get(self):
        # username =
        user_id = self.user.key().id()
        user_name = user_id and Userinfo.by_id(int(user_id))
        if user_name:
            self.render("profile.html", username=user_name.username)
        else:
            self.redirect('/signup')


class BlogFront(Handler):
    def get(self):
        if self.user:
            posts = db.GqlQuery("select * from Post order \
                                by created desc limit 10")
            self.render('bloghome.html', posts=posts)
        else:
            self.redirect('/login')


class BlogAll(Handler):
    def get(self):
        posts = db.GqlQuery("select * from Post order by created desc")
        self.render('bloghome.html', posts=posts)


class PostPage(Handler):
    def get(self, postid):
        if self.user:
            key = db.Key.from_path('Post', int(postid), parent=blog_key())
            post = db.get(key)
            comments = db.GqlQuery("select * from Comment where postid=" +
                                   postid + " order by created desc")
            likes = db.GqlQuery("select * from Like where postid=" + postid)
            if not post:
                self.error(404)
                return
            self.render("blogpage.html", post=post,
                        comments=comments, numlikes=likes.count())
        else:
            self.redirect('/login')

    def post(self, postid):
        key = db.Key.from_path('Post', int(postid), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        if(self.user):
            if(self.request.get('like') and
               self.request.get('like') == "update"):
                likes = db.GqlQuery("select * from Like where postid=" +
                                    postid +
                                    " and userid=" + str(self.user.key().id()))
                if self.user.key().id() == post.userid:
                    self.redirect("/blog/" + postid +
                                  "?error=You cannot like your " +
                                  "post.!!")
                elif likes.count() == 0:
                    l = Like(parent=blog_key(), userid=self.user.key().id(),
                             postid=int(postid))
                    l.put()

            if(self.request.get('comment')):
                comment = self.request.get('comment')
                c = Comment(parent=blog_key(), userid=self.user.key().id(),
                            postid=int(postid),
                            comment=comment)
                c.put()
            likes = db.GqlQuery("select * from Like where postid=" + postid)
            comments = db.GqlQuery("select * from Comment where postid=" +
                                   postid + "order by created desc")

            self.render("blogpage.html", post=post, comments=comments,
                        numlikes=likes.count())
        else:
            self.redirect("/login?error=You need to login before performing \
                          edit, like or commenting.!!")


class NewPost(Handler):
    def get(self):
        if self.user:
            self.render('blognew.html')
        else:
            self.redirect('/login')

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent=blog_key(), userid=self.user.key().id(),
                     subject=subject, content=content)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject & content, both are required!"
            self.render("blognew.html", subject=subject,
                        content=content, error=error)


class DeletePost(Handler):
    def get(self, postid):
        if self.user:
            key = db.Key.from_path('Post', int(postid), parent=blog_key())
            post = db.get(key)
            if post.userid == self.user.key().id():
                post.delete()
                self.redirect("/blog/?deledtedpostid=" + postid)
            else:
                self.redirect("/blog/" + postid + "?error=You don't have " +
                              "access to delete this record.")
        else:
            self.redirect("/login?error=You need to be logged, in order" +
                          " to delete your post!!")


class EditPost(Handler):
    def get(self, postid):
        if self.user:
            key = db.Key.from_path('Post', int(postid), parent=blog_key())
            post = db.get(key)
            if post.userid == self.user.key().id():
                self.render("blogedit.html", subject=post.subject,
                            content=post.content)
            else:
                self.redirect("/blog/" + postid + "?error=You don't have " +
                              "access to edit this record.")
        else:
            self.redirect("/login?error=You need to be logged, " +
                          "in order to edit your post!!")

    def post(self, postid):
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            key = db.Key.from_path('Post', int(postid), parent=blog_key())
            post = db.get(key)
            post.subject = subject
            post.content = content
            post.put()
            self.redirect('/blog/%s' % postid)
        else:
            error = "subject & content, both are required!"
            self.render("blogedit.html", subject=subject,
                        content=content, error=error)


class DeleteComment(Handler):
    def get(self, postid, comment_id):
        if self.user:
            key = db.Key.from_path('Comment', int(comment_id),
                                   parent=blog_key())
            c = db.get(key)
            if c.userid == self.user.key().id():
                c.delete()
                self.redirect("/blog/"+postid+"?deleted_comment_id=" +
                              comment_id)
            else:
                self.redirect("/blog/" + postid + "?error=You don't have " +
                              "access to delete this comment.")
        else:
            self.redirect("/login?error=You need to be logged, in order to " +
                          "delete your comment!!")


class EditComment(Handler):
    def get(self, postid, comment_id):
        if self.user:
            key = db.Key.from_path('Comment', int(comment_id),
                                   parent=blog_key())
            c = db.get(key)
            if c.userid == self.user.key().id():
                self.render("blogedit.html", comment=c.comment)
            else:
                self.redirect("/blog/" + postid +
                              "?error=You don't have access to edit this " +
                              "comment.")
        else:
            self.redirect("/login?error=You need to be logged, in order to" +
                          " edit your post!!")

    def post(self, postid, comment_id):
        if not self.user:
            self.redirect('/blog')

        comment = self.request.get('comment')

        if comment:
            key = db.Key.from_path('Comment',
                                   int(comment_id), parent=blog_key())
            comme = db.get(key)
            comme.comment = comment
            comme.put()
            self.redirect('/blog/%s' % postid)
        else:
            error = "if you are editing then comment can not be blank!"
            self.render("blogedit.html", comment=comment, error=error)

app = webapp2.WSGIApplication([('/?', Front),
                               ('/signup', SignUp),
                               ('/login', LogIn),
                               ('/logout', LogOut),
                               ('/profile/?', Profile),
                               ('/blog/?', BlogFront),
                               ('/blogall', BlogAll),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/blog/deletepost/([0-9]+)', DeletePost),
                               ('/blog/editpost/([0-9]+)', EditPost),
                               ('/blog/deletecomme/([0-9]+)/([0-9]+)',
                                DeleteComment),
                               ('/blog/editcomme/([0-9]+)/([0-9]+)',
                                EditComment),
                               ],
                              debug=True)


# to delete all data from database
# dev_appserver.py --clear_datastore=yes location_of_project

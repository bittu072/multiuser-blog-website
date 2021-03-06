# importing libraries
import os

import re
from string import letters

import jinja2
import webapp2
import string
import random

from blogdb import *


# this is for importing and using jinja2
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

# user, password, email validation
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)


EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)

# database declaration


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
            params['error_username'] = "not a valid username!!"
            have_error = True

        if not valid_password(password):
            params['error_password'] = "wasn't a valid password!!"
            have_error = True
        elif (password != verify):
            params['error_verify'] = "Your passwords didn't match!!"
            have_error = True

        if not valid_email(email):
            params['error_email'] = "not a valid email!!"
            have_error = True

        if have_error:
            self.render('signup.html', **params)
        else:
            # add cookies
            check_user_exist = Userinfo.by_name(username)
            if check_user_exist:
                self.render('signup.html',
                            error_username="User already exists, try another")
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
        # added error parametere to show error from editpost, deletepost, etc..
        self.render('login.html', error=self.request.get('error'))

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = Userinfo.login(username, password)
        if u:
            if u == "wrong password":
                self.render('login.html', error_password="wrong password!!")
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
            self.render('bloghome.html', posts=posts,
                        deletedpostid=self.request.get('deletedpostid'),
                        error=self.request.get('error'))
        else:
            self.redirect('/login?error=login before watching our secret \
                          million dollar worth post!!!!')


class BlogAll(Handler):
    def get(self):
        posts = db.GqlQuery("select * from Post order by created desc")
        if self.user:
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
                        comments=comments, numlikes=likes.count(),
                        error=self.request.get('error'))
        else:
            self.redirect('/login?error=login before watching our secret \
                          million dollar worth post!!!!')

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
                                  "?error=cannot like your " +
                                  "own post....sorry.!!")
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
            self.redirect("/login?error=login or signup if you want to \
                          edit, like or comment!!!")


class NewPost(Handler):
    def get(self):
        if self.user:
            self.render('blognew.html')
        else:
            self.redirect('/login')

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')

        if self.user:

            if subject and content:
                p = Post(parent=blog_key(), userid=self.user.key().id(),
                         subject=subject, content=content)
                p.put()
                self.redirect('/blog/%s' % str(p.key().id()))
            else:
                error = "subject & content, both are required!"
                self.render("blognew.html", subject=subject,
                            content=content, error=error)
        else:
            self.redirect("/login?error=login or signup if you want to \
                          edit, like or comment!!!")


class DeletePost(Handler):
    def get(self, postid):
        if self.user:
            key = db.Key.from_path('Post', int(postid), parent=blog_key())
            post = db.get(key)
            if post.userid == self.user.key().id():
                post.delete()
                self.redirect("/blog/?deletedpostid=" + postid)
            else:
                self.redirect("/blog/" + postid + "?error=You cannot \
                              delete this record. you didn't create this")
        else:
            self.redirect("/login?error=login before deleting post!!")


class EditPost(Handler):

    def get(self, postid):
        if self.user:
            key = db.Key.from_path('Post', int(postid), parent=blog_key())
            post = db.get(key)
            if post.userid == self.user.key().id():
                self.render("blogedit.html", subject=post.subject,
                            content=post.content)
            else:
                self.redirect("/blog/" + postid + "?error=You cannot \
                              edit this record. you didn't create this")
        else:
            self.redirect("/login?error=login before editing post!!")

    def post(self, postid):
        subject = self.request.get('subject')
        content = self.request.get('content')
        key = db.Key.from_path('Post', int(postid), parent=blog_key())
        post = db.get(key)

        if self.user:
            if post.userid == self.user.key().id():
                if subject and content:
                    key = db.Key.from_path('Post', int(postid),
                                           parent=blog_key())
                    post = db.get(key)
                    post.subject = subject
                    post.content = content
                    post.put()
                    self.redirect('/blog/%s' % postid)
                else:
                    error = "subject & content, both are required!"
                    self.render("blogedit.html", subject=subject,
                                content=content, error=error)
        else:
            self.redirect("/login?error=login or signup if you want to \
                          edit, like or comment!!!")


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
                self.redirect("/blog/" + postid + "?error=You cannot \
                               delete this comment. add your comment to try \
                               delete !!  :-)")
        else:
            self.redirect("/login?error=login before deleting comment!!")


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
                              "?error=You cannot edit this comment. \
                              add your comment to try edit !!  :-)")
        else:
            self.redirect("/login?error=login before editing comment!!")

    def post(self, postid, comment_id):
        comment = self.request.get('comment')
        key = db.Key.from_path('Comment', int(comment_id),
                               parent=blog_key())
        c = db.get(key)

        if self.user:
            if c.userid == self.user.key().id():
                if comment:
                    key = db.Key.from_path('Comment',
                                           int(comment_id), parent=blog_key())
                    comme = db.get(key)
                    comme.comment = comment
                    comme.put()
                    self.redirect('/blog/%s' % postid)
                else:
                    error = "while editing then comment can not be blank!"
                    self.render("blogedit.html", comment=comment, error=error)
        else:
            self.redirect("/login?error=login or signup if you want to \
                          edit, like or comment!!!")

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

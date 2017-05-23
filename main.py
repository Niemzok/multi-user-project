# Copyright 2016 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import os
import re
import random
import hashlib
import string
import sys
import hmac

import jinja2
import webapp2

from google.appengine.ext import db

from models import Blog, User, Comment

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

SECRET = '50DC2590767F20A75420ADDE345E339D'

BASE_URL = 'http://udacity-157413.appspot.com/'
LOGOUT_URL = '/logout'
SIGNUP_URL = '/signup'
NEWPOST_URL = '/blog/newpost'
MAIN_URL = '/blog'


class Handler(webapp2.RequestHandler):
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    EMAIL_RE = re.compile("^[\S]+@[\S]+.[\S]+$")
    PASSWORD_RE = re.compile("^.{3,20}$")

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def valid_username(self, username):
        return self.USER_RE.match(username)

    def valid_email(self, email):
        return self.EMAIL_RE.match(email)

    def valid_password(self, password):
        return self.PASSWORD_RE.match(password)

    def make_salt(self):
        return ''.join(random.choice(string.letters) for x in xrange(5))

    def make_secure_val(self, val):
        h = hmac.new(SECRET, val).hexdigest()
        return '%s|%s' % (val, h)

    def valid_val(self, h):
        if h:
            val = h.split('|')[0]
            return self.make_secure_val(val) == h

    def unique_username(self, username):
        result = []
        db_user = self.lookup_user(username)
        for u in db_user:
            result.append(u.username)
        return len(result) == 0

    def lookup_user(self, username):
        query = User.query().filter(User.username == username)
        db_user = query.fetch(1)
        return db_user

    def make_salt(self):
        return ''.join(random.choice(string.letters) for x in xrange(5))

    def make_pw_hash(self, name, pw, salt=None):
        if salt is None:
            salt = self.make_salt()
        h = hashlib.sha256(name + pw + salt).hexdigest()
        return '%s,%s' % (h, salt)

    def valid_pw(self, name, pw, h):
        salt = h.split(',')[1]
        return self.make_pw_hash(name, pw, salt) == h

    def logged_in_user(self):
        user_id_hash = self.request.cookies.get('user_id')
        if self.valid_val(user_id_hash):
            user = User.get_by_id(int(user_id_hash.split('|')[0]))
            return user

    @staticmethod
    def login_required(func):
        """
        A decorator to confirm a user is logged in or redirect as needed.
        """
        def login(self, *args, **kwargs):
            user = self.logged_in_user()
            # Redirect to login if user not logged in, else execute func.
            if not user:
                self.redirect("/login")
            else:
                func(self, *args, **kwargs)
        return login


class UpvoteHandler(Handler):
    @Handler.login_required
    def post(self):
        user = self.logged_in_user()
        upvote = self.request.get("upvote")
        post_id = self.request.get("post_id")
        if upvote:
            post = Blog.get_by_id(int(post_id))
            if post is not None:
                if user.key not in post.upvotes:
                    post.upvotes.append(user.key)
                    post.put()
        self.redirect('/blog')


class MainPage(UpvoteHandler):
    def render_front(self, username="", error=""):
        qry = Blog.query().order(-Blog.date_created)
        blogs = qry.fetch(10)
        self.render("front.html", error=error, username=username, posts=blogs,
                    base_url=BASE_URL, logout_url=LOGOUT_URL,
                    newpost_url=NEWPOST_URL, main_url=MAIN_URL)

    @UpvoteHandler.login_required
    def get(self):
        user = self.logged_in_user()
        self.render_front(user.username)


class NewBlog(Handler):
    @Handler.login_required
    def get(self):
        self.render("newblog.html", base_url=BASE_URL, main_url=MAIN_URL)

    @Handler.login_required
    def post(self):
        user = self.logged_in_user()
        subject = self.request.get("subject")
        body = self.request.get("content")
        if subject and body:
            blog = Blog(subject=subject, body=body, author=user.key)
            blog.put()
            post_id = blog.key.integer_id()
            self.redirect('/blog/%s' % post_id)
        else:
            error = "You need a headliner and content for your blog post."
            self.render("newblog.html", subject=subject, content=body,
                        error=error)


class BlogPost(Handler):
    def render_post(self, post_id="", username="", error=""):
        post = Blog.get_by_id(int(post_id))
        created = post.date_created.strftime('%d/%m/%y %H:%M')
        author = post.author
        qry = Comment.query().order(-Comment.date_created).filter(
              Comment.post == post.key)
        comments = qry.fetch()
        self.render("post.html", error=error, subject=post.subject,
                    body=post.body, date_created=created, username=username,
                    author=author.get().username, post_id=str(post.key.id()),
                    base_url=BASE_URL, main_url=MAIN_URL, comments=comments)

    @Handler.login_required
    def get(self, post_id):
        user = self.logged_in_user()
        self.render_post(post_id=post_id, username=user.username)

    @Handler.login_required
    def post(self, post_id):
        user = self.logged_in_user()
        post = Blog.get_by_id(int(post_id))
        delete = self.request.get("delete")
        comment = self.request.get("comment")
        if delete and user.key == post.author:
            post.key.delete()
            self.redirect(MAIN_URL)
        elif comment:
            comm = Comment(comment=comment, author=user.key, post=post.key)
            comm.put()
            self.render_post(post_id=post_id, username=user.username)
        else:
            self.render_post(post_id=post_id, username=user.username)


class EditPost(Handler):
    @Handler.login_required
    def get(self, post_id):
        user = self.logged_in_user()
        post = Blog.get_by_id(int(post_id))
        if user.key == post.author:
            subject = post.subject
            content = post.body
            self.render("newblog.html", base_url=BASE_URL, main_url=MAIN_URL,
                        subject=subject, content=content)
        else:
            self.redirect(MAIN_URL)

    @Handler.login_required
    def post(self, post_id):
        user = self.logged_in_user()
        subject = self.request.get("subject")
        body = self.request.get("content")
        if subject and body:
            post = Blog.get_by_id(int(post_id))
            post.subject = subject
            post.body = body
            post.put()
            post_id = post.key.integer_id()
            self.redirect('/blog/%s' % post_id)
        else:
            error = "You need a headliner and content for your blog post."
            self.render("newblog.html", subject=subject, content=body,
                        error=error)


class SignUp(Handler):
    def write_form(self, user_error="", email_error="", password_error="",
                   verify_error="", username="", email=""):
        self.render("signup.html", user_error=user_error,
                    email_error=email_error, password_error=password_error,
                    verify_error=verify_error, username=username, email=email)

    def get(self):
        self.write_form()

    def post(self):
        user_error = ""
        email_error = ""
        password_error = ""
        verify_error = ""
        username = self.request.get("username")
        email = self.request.get("email")
        password = self.request.get("password")
        verify = self.request.get("verify")

        u_username = self.valid_username(username)
        if email:
            u_email = self.valid_email(email)
        else:
            u_email = "No email"
        u_password = self.valid_password(self.request.get("password"))

        if not self.unique_username(username):
            user_error = "This user already existis"
            self.write_form(user_error, email_error, password_error,
                            verify_error, username, email)

        elif not(u_username and u_email and u_password and (
                 password == verify)):
            if not u_username:
                user_error = "This is not a valid username."
            if not u_email:
                email_error = "This is not a valid email."
            if not u_password:
                password_error = "This is not a valid password."
            if not password == verify:
                verify_error = "Your passwords did not match."

            self.write_form(user_error, email_error, password_error,
                            verify_error, username, email)
        else:
            user = User(username=username, password=self.make_pw_hash(
                        username, password), email=email)
            user.put()
            user_id = str(user.key.id())
            self.response.headers.add('Set-Cookie', str('user_id=%s;
                                      Path=/' % self.make_secure_val(user_id)))
            self.redirect('/welcome')


class Login(Handler):
    def write_form(self, login_error=""):
            self.render("login.html", login_error=login_error)

    def get(self):
        self.write_form()

    def post(self):
        login_error = ""
        username = self.request.get("username")
        password = self.request.get("password")

        user = self.lookup_user(username)[0]

        if user and self.valid_pw(username, password, user.password):
            user_id = str(user.key.id())
            self.response.headers.add('Set-Cookie', str('user_id=%s;
                                      Path=/' % self.make_secure_val(user_id)))
            self.redirect('/welcome')


class Logout(Handler):
    def get(self):
        self.response.headers.add('Set-Cookie', str('user_id=; Path=/'))
        self.redirect(SIGNUP_URL)


class Welcome(Handler):
    """docstring for Welcome."""
    @Handler.login_required
    def get(self):
        user = self.logged_in_user()
        self.render("welcome.html", username=user.username, base_url=BASE_URL)

app = webapp2.WSGIApplication([(r'/blog', MainPage),
                              (NEWPOST_URL, NewBlog),
                              (r'/blog/(\d+)', BlogPost),
                              (r'/signup', SignUp),
                              (r'/welcome', Welcome),
                              (r'/login', Login),
                              (LOGOUT_URL, Logout),
                              (r'/', MainPage),
                              (r'/blog/(\d+)/edit', EditPost)],
                              debug=True)

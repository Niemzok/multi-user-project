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
import datetime

import jinja2
import webapp2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
EMAIL_RE = re.compile("^[\S]+@[\S]+.[\S]+$")
PASSWORD_RE = re.compile("^.{3,20}$")

SECRET = '50DC2590767F20A75420ADDE345E339D'

BASE_URL ='http://localhost:8080'
LOGOUT_URL = '/logout'
SIGNUP_URL = '/signup'
NEWPOST_URL = '/blog/newpost'



class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def valid_username(self, username):
        return USER_RE.match(username)

    def valid_email(self, email):
        return EMAIL_RE.match(email)

    def valid_password(self, password):
        return PASSWORD_RE.match(password)

    def make_salt(self):
        return ''.join(random.choice(string.letters) for x in xrange(5))

    def make_secure_val(self, val):
        h = hmac.new(SECRET, val).hexdigest()
        return '%s|%s' % (val, h)

    def valid_val(self, h):
        ###Your code here
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
        db_user = User.all().filter('username =', username)
        return db_user

    def make_salt(self):
        return ''.join(random.choice(string.letters) for x in xrange(5))

    def make_pw_hash(self, name, pw, salt=None):
        if salt == None:
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



class Blog(db.Model):
    subject = db.StringProperty(required = True)
    body = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    author = db.StringProperty(required = True)
    upvotes = db.IntegerProperty(required = False)

class User(db.Model):
    username = db.StringProperty(required=True)
    password = db.StringProperty(required=True)
    email = db.StringProperty(required=False)
    registered = db.DateTimeProperty(auto_now_add = True)


class MainPage(Handler):
    def render_front(self, username = "", error=""):
        blogs = db.GqlQuery("SELECT * FROM Blog "
                        "ORDER BY created DESC")
        self.render("front.html", error=error, username=username, blogs=blogs,
                                  base_url=BASE_URL, logout_url=LOGOUT_URL,
                                  newpost_url=NEWPOST_URL)

    def get(self):
        user = self.logged_in_user()
        if user:
            self.render_front(user.username)
        else:
            self.redirect('/signup')

    def post(self):
        upvote = self.request.get("upvote")
        post_id = self.request.get("post_id")
        print "post id:", post_id
        if upvote:
            post = Blog.get_by_id(int(post_id))
            if post.upvotes:
                post.upvotes += 1
            else:
                post.upvotes = 1
            post.put()
        user = self.logged_in_user()
        if user:
            self.render_front(user.username)


class NewBlog(Handler):
    def get(self):
        user = self.logged_in_user()
        if user:
            self.render("newblog.html")
        else:
            self.redirect('/signup')


    def post(self):
        user = self.logged_in_user()
        subject = self.request.get("subject")
        body = self.request.get("content")
        if subject and body:
            blog = Blog(subject=subject, body=body, author=user.username)
            blog.put()
            post_id = blog.key().id()
            self.redirect('/blog/%s' % post_id )
        else:
            error = "You need a headliner and content for your blog post."
            self.render("newblog.html", subject=subject, content=body, error=error)

class BlogPost(Handler):
    def render_post(self, post_id="", username="", error=""):
        post = Blog.get_by_id(int(post_id))
        created = post.created.strftime('%d/%m/%y %H:%M')
        self.render("post.html", error=error, subject=post.subject,
                     body=post.body, date_created=created, username=username,
                     author=post.author, base_url=BASE_URL)

    def get(self, post_id):
        user = self.logged_in_user()
        if user:
            self.render_post(post_id=post_id, username=user.username)
        else:
            self.redirect('/signup')


class SignUp(Handler):
    """docstring for SignUp."""
    def write_form(self, user_error="", email_error="", password_error="", verify_error="",
                    username="", email=""):
        self.render("signup.html", user_error=user_error,
                                   email_error=email_error,
                                   password_error=password_error,
                                   verify_error=verify_error,
                                   username=username,
                                   email=email)

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

        elif not(u_username and u_email and u_password and (password == verify)):
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
            user = User(username=username, password=self.make_pw_hash(username, password), email=email)
            user.put()
            user_id = str(user.key().id())
            self.response.headers.add('Set-Cookie', str('user_id=%s; Path=/' % self.make_secure_val(user_id)))
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

        user = self.lookup_user(username)

        if user and self.valid_pw(username, password, user[0].password):
            user_id = str(user[0].key().id())
            self.response.headers.add('Set-Cookie', str('user_id=%s; Path=/' % self.make_secure_val(user_id)))
            self.redirect('/welcome')

class Logout(Handler):
    def get(self):
        self.response.headers.add('Set-Cookie', str('user_id=; Path=/'))
        self.redirect(SIGNUP_URL)




class Welcome(Handler):
    """docstring for Welcome."""
    def get(self):
        user = self.logged_in_user()
        if user:
            self.render("welcome.html", username=user.username, base_url=BASE_URL)

        else:
            self.redirect('/signup')





app = webapp2.WSGIApplication([(r'/blog', MainPage),
                              (NEWPOST_URL, NewBlog),
                              (r'/blog/(\d+)', BlogPost),
                              (r'/signup', SignUp),
                              (r'/welcome', Welcome),
                              (r'/login', Login),
                              (LOGOUT_URL, Logout),
                              (r'/', MainPage) ]
                               , debug=True)

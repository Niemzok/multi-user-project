from google.appengine.ext import ndb

class User(ndb.Model):
    username = ndb.StringProperty(required=True)
    password = ndb.StringProperty(required=True)
    email = ndb.StringProperty(required=False)
    registered = ndb.DateTimeProperty(auto_now_add = True)

class Blog(ndb.Model):
    subject = ndb.StringProperty(required = True)
    body = ndb.TextProperty(required = True)
    date_created = ndb.DateTimeProperty(auto_now_add = True)
    author = ndb.KeyProperty(User, required = True)
    upvotes = ndb.KeyProperty(User, repeated=True, required = False)

class Comment(ndb.Model):
    comment = ndb.TextProperty(required = True)
    date_created = ndb.DateTimeProperty(auto_now_add = True)
    author = ndb.KeyProperty(User, required = True)
    post = ndb.KeyProperty(Blog, required = True)

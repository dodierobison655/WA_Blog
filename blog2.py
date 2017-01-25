import webapp2
import logging
import re
import cgi
import jinja2
import os
import random
import string
import hashlib
import hmac
import Cookie 
import datetime
import json
import urllib2
from google.appengine.ext import db

## see http://jinja.pocoo.org/docs/api/#autoescaping
def guess_autoescape(template_name):
   if template_name is None or '.' not in template_name:
      return False
      ext = template_name.rsplit('.', 1)[1]
      return ext in ('xml', 'html', 'htm')

JINJA_ENVIRONMENT = jinja2.Environment(
   autoescape=guess_autoescape,     ## see http://jinja.pocoo.org/docs/api/#autoxscaping
   loader=jinja2.FileSystemLoader(os.path.dirname(__file__)),
   extensions=['jinja2.ext.autoescape'])

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")  # 3-20 characters (A-Za-z0-9_-)
def valid_username(username):
   return USER_RE.match(username)

PASSWORD_RE = re.compile(r"^.{4,20}$")          # 4-20 characters (any)
def valid_password(username):
   return PASSWORD_RE.match(username)

EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
def valid_email(username):
   return EMAIL_RE.match(username)

class BlogHandler(webapp2.RequestHandler):
   def write(self, *items):    
      self.response.write(" : ".join(items))

   def render_str(self, template, **params):
      tplt = JINJA_ENVIRONMENT.get_template('templates/'+template)
      return tplt.render(params)

   def render(self, template, **kw):
      self.write(self.render_str(template, **kw))
   def render_json(self, d):
      json_txt = json.dumps(d)
      self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
      self.write(json_txt)


def make_salt():
   salt = ""
   for i in range(0, 25):
      salt += string.ascii_letters[random.randint(0,51)]
   return salt

def make_pw_hash(name, pw, salt=None):
   if not salt:
      salt = make_salt()
   return hashlib.sha256(name+pw+salt).hexdigest()+'|'+salt

def valid_pw(name, pw, h):
   salt = h.split('|')[1]
   return h == make_pw_hash(name, pw, salt)

SECRET="imasecret"
def hash_str(s):
   return hmac.new(SECRET,s).hexdigest()

def make_secure_val(s):
   return s+'|'+hash_str(s)

def check_secure_val(h):
   val = h.split('|')[0]
   if (h == make_secure_val(val)):
      return val
def get_coords(x):
    p = urllib2.urlopen("http://freegeoip.net/json/" + x)
    r = json.loads(p.read())
    if r['ip'] == "0.0.0.0":
        print "None"
    else:
        print "("+str(r['latitude'])+","+str(r['longitude'])+")"
        return db.GeoPt(str(r['latitude'])+","+str(r['longitude']))
class Blog(db.Model):
   subject = db.StringProperty()
   content = db.StringProperty()
   created = db.DateTimeProperty(auto_now_add = True)
   coords  = db.GeoPtProperty()
   
   
   def as_dict(self):
      time_fmt = '%c'
      d = {'subject' : self.subject,
           'content' : self.content,
           'created' : self.created.strftime(time_fmt)}
      return d


class MyUsers(db.Model):
   username   = db.StringProperty()   
   pwhashsalt = db.StringProperty()
   email      = db.StringProperty()
   created    = db.DateTimeProperty(auto_now_add = True)

class BlogFront(BlogHandler):
   def get(self):
      posts = db.GqlQuery("SELECT * FROM Blog "
                          "ORDER BY created DESC limit 10 ")
      if self.request.url.endswith('.json'):
        self.render_json([post.as_dict() for post in posts])
      else:
          user_id_cookie_from_browser = self.request.cookies.get('user_id')
          logging.info(user_id_cookie_from_browser)
          if user_id_cookie_from_browser:
             user_id = check_secure_val(user_id_cookie_from_browser)
             user = MyUsers.get_by_id(int(user_id))
             username = user.username
          else:
             username = ""
          logging.info("********** BlogFront Page GET **********")
          posts = db.GqlQuery("SELECT * FROM Blog "
                              "ORDER BY created DESC limit 10 ")
          self.render("posts.html", posts=posts, username = username)

class Permalink(BlogHandler):
   def get(self, post_id):
      posts = db.GqlQuery("SELECT * FROM Blog "
                          "ORDER BY created DESC limit 10 ")
      logging.info("********** Permalink Page GET **********")
      if self.request.url.endswith('.json'):
          self.render_json([post.as_dict() for post in posts])
      else:
          user_id_cookie_from_browser = self.request.cookies.get('user_id')
          user_id = check_secure_val(user_id_cookie_from_browser)
          if user_id:
             user = MyUsers.get_by_id(int(user_id))
             username = user.username
          else:
             username = ""
             self.redirect("/blog/logout/")
          post = Blog.get_by_id(int(post_id))
     
          self.render("permalink.html",
                      subject = post.subject,
                      date    = str(post.created.date().strftime("%A %B %d, %Y"))+" "+str(post.created.time().strftime("%X %z")),
                      content = post.content,
                      username = username)


class NewPost(BlogHandler):
   def get(self):
      logging.info("********** NewPost Page GET **********")
      user_id_cookie_from_browser = self.request.cookies.get('user_id')
      user_id = check_secure_val(user_id_cookie_from_browser)
      if user_id:
         user = MyUsers.get_by_id(int(user_id))
         username = user.username
      else:
         username = ""
         self.redirect("/blog/logout")
      self.render("newpost.html",username=username)

   def post(self):
      logging.info("********** NewPost Page POST **********")

      subject = self.request.get('subject')
      content = self.request.get('content')
      ip = self.request.get('ip')

      if subject and content:
         ## b = Blog()
         ## b.subject = subject
         ## b.content = content
         b = Blog(subject=subject, content=content, coords = get_coords(ip))
         b.put()
         id = b.key().id()
         self.redirect('/blog/'+str(id))
      else:
         error_msg = "Please provide both a subject and content"
         self.render("newpost.html",
                     ph_subject=subject,
                     ph_content=content,
                     ph_error=error_msg)

class SignUp(BlogHandler):
   def write_signup(self, username_error_msg="", password_error_msg="", verify_error_msg="", \
                    email_error_msg="", user_username="", user_email=""):
      template_values = {'error_username': username_error_msg,
                         'error_password': password_error_msg,
                         'error_verify'  : verify_error_msg,
                         'error_email'   : email_error_msg,
                         'username_value': user_username,
                         'email_value'   : user_email}
      template = JINJA_ENVIRONMENT.get_template('templates/signup.html')
      self.response.write(template.render(template_values))

   def get(self):
      logging.info("********** SignUp Page GET **********")
      self.write_signup()

   def post(self):
      logging.info("********** SignUp Page POST **********")
      user_username = self.request.get('username')
      user_password = self.request.get('password')
      user_verify   = self.request.get('verify')
      user_email    = self.request.get('email')

      user_username_v = valid_username(user_username)
      user_password_v = valid_password(user_password)
      user_verify_v   = valid_password(user_verify)
      user_email_v    = valid_email(user_email)

      username_error_msg = password_error_msg = verify_error_msg = email_error_msg = ""
      if not(user_username_v):
         username_error_msg = "That's not a valid username."

      if (user_password != user_verify):
         password_error_msg = "Passwords do not match."
      elif not(user_password_v):
         password_error_msg = "That's not a valid password."
         if (user_email != "") and not(user_email_v):
            email_error_msg = "That's not a valid email."

      ## this should also work   userQuery = db.GqlQuery("SELECT * FROM MyUsers WHERE username = :1", user_username)      
      userQuery = db.GqlQuery("SELECT * FROM MyUsers WHERE username = '%s'" % user_username)
      if not(userQuery.count() == 0 or userQuery.count() == 1): 
         logging.info("***DBerr(signup) username = " + user_username + " (count = " + str(userQuery.count()) + ")" )
      user = userQuery.get() ## .get() returns Null if no results are found for the database query

      if user and user.username == user_username:   ## not really necessay to see if usernames are equal, since query would only have returned if there was a match
         user_username_v = False
         username_error_msg = "That user already exists."

      logging.info("DBG: The inputs="      \
                   +user_username + " " \
                   +user_password + " " \
                   +user_verify   + " " \
                   +user_email)

      logging.info("DBG: The valids="+str(bool(user_username_v))+" " \
                   +str(bool(user_password_v))+" " \
                   +str(bool(user_verify_v))  +" " \
                   +str(bool(user_email_v)))

      if not(user_username_v and user_password_v and user_verify_v and ((user_email == "") or user_email_v) and (user_password == user_verify)):
         self.write_signup(username_error_msg, password_error_msg, verify_error_msg, \
                           email_error_msg, user_username, user_email)
      else:
         pw_hash = make_pw_hash(user_username, user_password)
         u = MyUsers(username=user_username, pwhashsalt=pw_hash, email=user_email)
         u.put()
         id = u.key().id()
         self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' % make_secure_val(str(id)))
         self.redirect("/blog/welcome")

class MapHandler(BlogHandler):
    def get(self):
        posts = db.GqlQuery("SELECT * FROM Blog "
                          "ORDER BY created DESC limit 10 ")
        values = ""
        for i in posts:
            if i.coords:
                values += "&markers="+str(i.coords)
                logging.info(values)
        template_values = {'values' : values}
        template = JINJA_ENVIRONMENT.get_template('templates/map.html')
        self.response.write(template.render(template_values))

class LogIn(BlogHandler):
   def write_login(self, error=""):
      template_values = {'error': error}
      template = JINJA_ENVIRONMENT.get_template('templates/login.html')
      self.response.write(template.render(template_values))

   def get(self):
      logging.info("********** LogIn Page GET **********")
      self.write_login()

   def post(self):
      logging.info("***DBG: LogIn Page POST")
      user_username = self.request.get('username')
      user_password = self.request.get('password')

      ## NOTE: make sure that username is a db.StringProperty() and not db.TextProperty
      ## this should also work   userQuery = db.GqlQuery("SELECT * FROM MyUsers WHERE username = :1", user_username)      
      userQuery = db.GqlQuery("SELECT * FROM MyUsers WHERE username = '%s'" % user_username)
      if not(userQuery.count() == 0 or userQuery.count() == 1): 
         logging.info("***DBerr (login) username = " + user_username + " (count = " + str(userQuery.count()) + ")" )
      user = userQuery.get() ## .get() returns Null if no results are found for the database query

      logging.info(">>> username=" + str(user_username) + " type=" + str(type(user_username)))
      self.write("username",user_username)
             
      if user and user.username == user_username and valid_pw(user_username,user_password,user.pwhashsalt):  ## not really necessay to see if usernames are equal, since query would only have returned if there was a match
         id = user.key().id()
         self.response.headers.add_header('Set-Cookie','user_id=%s; max-age=60; Path=/' % make_secure_val(str(id)))
         self.redirect("/blog/welcome")
      else:
         self.write_login("Invalid login")
         

class WelcomePage(BlogHandler):
   def write_welcome(self, username=""):
      template_values = {'username': username}
      template = JINJA_ENVIRONMENT.get_template('templates/welcome.html')
      self.response.write(template.render(template_values))

   def get(self):
      logging.info("********** WelcomePage GET **********")
      user_id_cookie_from_browser = self.request.cookies.get('user_id')
      user_id = check_secure_val(user_id_cookie_from_browser)
      if user_id:
         user = MyUsers.get_by_id(int(user_id))
         self.write_welcome(user.username)
      else:
         username = ""
         self.redirect("/blog/logout")


class LogoutPage(BlogHandler):
   def get(self):
      expires = datetime.datetime.utcnow() + datetime.timedelta(0,60)
      self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
      self.redirect("/blog/")


class MainPage(BlogHandler):
   def get(self):
      logging.info("********** MainPage GET **********")
      self.redirect('/blog')


application = webapp2.WSGIApplication([
   ('/', MainPage),
   (r'/blog/?(?:\.json)?', BlogFront),
   (r'/blog/newpost/?', NewPost),
   (r'/blog/(\d+)(?:\.json)?', Permalink),  ## anything in parenthesis is passed as a parameter to Permalink
   (r'/blog/signup/?', SignUp),
   (r'/blog/login/?', LogIn),
   (r'/blog/map/?', MapHandler),
   (r'/blog/welcome/?', WelcomePage),
   (r'/blog/logout/?', LogoutPage),
], debug=True)

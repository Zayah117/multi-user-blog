import os
import webapp2
import jinja2
import re
import random
import string
import hashlib

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

# If I want to clear the database of users and blogposts
def clear_database():
        my_users = db.GqlQuery("SELECT * FROM User")
        my_posts = db.GqlQuery("SELECT * FROM Blogpost")
        my_comments = db.GqlQuery("SELECT * FROM Comment")

	db.delete(my_users)
	db.delete(my_posts)
	db.delete(my_comments)

# Validating user inputs
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")

def valid_username(username):
        return USER_RE.match(username)

def valid_password(password):
	return PASS_RE.match(password)

def valid_email(email):
	if email == "":
		return True
	else:
		return EMAIL_RE.match(email)

secret = "Tabs>Spaces"

# Security functions
def make_secure_val(val):
	return '%s|%s' % (val, hashlib.sha256(secret + val).hexdigest())

def check_secure_val(secure_val):
        if secure_val:
                val = secure_val.split('|')[0]
                if secure_val == make_secure_val(val):
                        return val

# Base Handler class
class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

	# Extra functions
	def set_secure_cookie(self, name, val):
		cookie_val = make_secure_val(val)
		self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' % (name, cookie_val))

	def read_secure_cookie(self, name):
		cookie_val = self.request.cookies.get(name)
		# return cookie_val if it's secure
		return cookie_val and check_secure_val(cookie_val)

	def login(self, user):
		self.set_secure_cookie('user_id', str(user.key().id()))

	def logout(self):
		self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

# Main page
class MainPage(Handler):
	def get(self):
		blog_posts = db.GqlQuery("SELECT * FROM Blogpost ORDER BY created DESC")

		self.render("mainpage.html", blog_posts=blog_posts)

# New posts
class NewPost(Handler):
	def get(self):
		self.render("newpost.html")

	def post(self):
		user_cookie = self.request.cookies.get("user_id")
		if check_secure_val(user_cookie):
			user_id = user_cookie.split('|')[0]
			username = User.by_id(int(user_id)).name

                        subject = self.request.get("subject")
                        content = self.request.get("content")
			writer = username
			if subject and content:
                                p = Blogpost(subject = subject, content = content, writer = writer)
                                p.put()

                                self.redirect("/blog/%s" % p.key().id())
                        else:
                                self.render("newpost.html")
		else:
                        self.redirect("/blog/login")

# For editing posts
class EditPost(Handler):
        def get(self, blog_id):
                my_blog = Blogpost.get_by_id(int(blog_id))
                self.render("edit.html", post=my_blog)
        def post(self, blog_id):
                my_blog = Blogpost.get_by_id(int(blog_id))

                user_cookie = self.request.cookies.get("user_id")
		if check_secure_val(user_cookie):
                        user_id = user_cookie.split('|')[0]
			username = User.by_id(int(user_id)).name
			
			if username == my_blog.writer:
                                new_subject = self.request.get("subject")
                                new_content = self.request.get("content")
                                
                                my_blog.subject = new_subject
                                my_blog.content = new_content
                                my_blog.put()

                self.redirect("/blog/%s" % blog_id)

# Permalink to blog posts
class Permalink(Handler):
	def get(self, blog_id):
		my_blog = Blogpost.get_by_id(int(blog_id))
		my_comments = Comment.gql("WHERE post=:1 ORDER BY created ASC", my_blog)
		self.render("permalink.html", post=my_blog, my_comments=my_comments)

        def post(self, blog_id):
                my_blog = Blogpost.get_by_id(int(blog_id))
                comment_text = self.request.get("comment")
                if comment_text:
                        user_cookie = self.request.cookies.get("user_id")
                        
                        if check_secure_val(user_cookie):
                                user_id = user_cookie.split('|')[0]
                                username = User.by_id(int(user_id)).name
                                
                                c = Comment(writer = username, comment = comment_text, post = my_blog)
                                c.put()
                        else:
                                self.redirect("/blog/login")

                my_comments = Comment.gql("WHERE post=:1 ORDER BY created ASC", my_blog)

                self.render("permalink.html", post=my_blog, my_comments=my_comments)

# For deleting posts
class Delete(Handler):
	def get(self, blog_id):
		my_blog = Blogpost.get_by_id(int(blog_id))
		
		user_cookie = self.request.cookies.get("user_id")
		if check_secure_val(user_cookie):
                        user_id = user_cookie.split('|')[0]
			username = User.by_id(int(user_id)).name
			
			if username == my_blog.writer:
                                my_comments = Comment.gql("WHERE post=:1 ORDER BY created ASC", my_blog)
                                db.delete(my_blog)
                                db.delete(my_comments)

                self.redirect("/blog")
      

# Signup page
class Signup(Handler):
	def get(self):
		self.render("user-signup.html")

        def post(self):
		self.username = self.request.get("username")
		self.password = self.request.get("password")
		self.verify = self.request.get("verify")
		self.email = self.request.get("email")

		if valid_username(self.username) and valid_password(self.password) and valid_email(self.email) and self.password == self.verify:
			u = User.by_name(self.username)
			if u:
                                username_error = "User already exists"
				self.render("user-signup.html", username_error=username_error)
			else:
				u = User.register(self.username, self.password, self.email)
				u.put()

				self.login(u)
				self.redirect('/blog/welcome')
		else:
			username_error = ""
			password_error = ""
			verify_error = ""
			email_error = ""

			if valid_username(self.username) == None:
				username_error = "Invalid username"
			if valid_password(self.password) == None:
				password_error = "Invalid password"
			if valid_email(self.email) == None:
				email_error = "Invalid email"
			if self.password != self.verify:
				verify_error = "Passwords do not match"
			self.render("user-signup.html", username=self.username,
							email=self.email,
							username_error=username_error,
							password_error=password_error,
							verify_error=verify_error,
							email_error=email_error)

# Login page
class Login(Handler):
	def get(self):
		self.render("user-login.html")
	def post(self):
                self.username = self.request.get("username")
		self.password = self.request.get("password")

		u = User.by_name(self.username)
		if u:
			salt = u.pw_hash.split(',')[0]
			p = make_pw_hash(self.username, self.password, salt)

			if u.pw_hash == p:
				self.login(u)
				self.redirect('/blog/welcome')
			else:
				password_error = "Invalid password"
				self.render("user-login.html", password_error=password_error)
		else:
			username_error = "User does not exist"
			self.render("user-login.html", username_error=username_error)

# Logout
class Logout(Handler):
	def get(self):
		self.logout()
		self.redirect('/blog/login')

# Welcome page
class Welcome(Handler):
	def get(self):
		user_cookie = self.request.cookies.get("user_id")
		if check_secure_val(user_cookie):
			user_id = user_cookie.split('|')[0]
			username = User.by_id(int(user_id)).name
			self.render('welcome.html', username = username)
		else:
			self.redirect('/blog/signup')

# Blogpost model
class Blogpost(db.Model):
	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	writer = db.StringProperty(required = True)

# Comment model
class Comment(db.Model):
        writer = db.StringProperty(required = True)
        comment = db.TextProperty(required = True)
        post = db.ReferenceProperty(Blogpost, collection_name='post_comments')
        created = db.DateTimeProperty(auto_now_add = True)

# User stuff
def make_salt():
	return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw, salt = None):
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(name + pw + salt).hexdigest()
	return salt + ',' + h

def valid_pw(name, password, h):
	salt = h.split(',')[0]
	return h == make_pw_hash(name, password, salt)

class User(db.Model):
	name = db.StringProperty(required = True)
	pw_hash = db.StringProperty(required = True)
	email = db.StringProperty()

	@classmethod
	def by_id(cls, uid):
		return User.get_by_id(uid)

	@classmethod
	def by_name(cls, name):
		u = User.all().filter('name = ', name).get()
		return u

	@classmethod
	def register(cls, name, pw, email = None):
		pw_hash = make_pw_hash(name, pw)
		return User(name = name, pw_hash = pw_hash, email = email)

	@classmethod
	def login(cls, name, pw):
		pass

# clear_database()
app = webapp2.WSGIApplication([('/blog', MainPage),
                               ('/blog/newpost', NewPost),
                               ('/blog/(\d+)', Permalink),
                               ('/blog/delete/(\d+)', Delete),
                               ('/blog/edit/(\d+)', EditPost),
                               ('/blog/signup', Signup),
                               ('/blog/login', Login),
                               ('/blog/welcome', Welcome),
                               ('/blog/logout', Logout)], debug=True)

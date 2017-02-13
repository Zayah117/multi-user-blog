"""
Main file for multi user blog project.
Created by Isaiah Baker: https://github.com/Zayah117
"""

import os
import re
import random
import string
import hashlib
import jinja2  # pylint: disable=import-error
import webapp2  # pylint: disable=import-error
from google.appengine.ext import db  # pylint: disable=import-error


TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), 'templates')
JINJA_ENV = jinja2.Environment(loader=jinja2.FileSystemLoader(TEMPLATE_DIR), autoescape=True)


def clear_database():
    """
    Clear database of posts,
    users, and comments.
    """
    my_users = db.GqlQuery("SELECT * FROM User")
    my_posts = db.GqlQuery("SELECT * FROM Blogpost")
    my_comments = db.GqlQuery("SELECT * FROM Comment")

    db.delete(my_users)
    db.delete(my_posts)
    db.delete(my_comments)


# Validating user inputs
def valid_username(username):
    """Return true if username is valid"""
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")

    return USER_RE.match(username)


def valid_password(password):
    """Return true if password is valid"""
    PASS_RE = re.compile(r"^.{3,20}$")

    return PASS_RE.match(password)


def valid_email(email):
    """Return true if email is valid"""
    EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
    
    if email == "":
        return True
    else:
        return EMAIL_RE.match(email)


SECRET = "Tabs>Spaces"


# Security functions
def make_secure_val(val):
    """Make secure hash"""
    return '%s|%s' % (val, hashlib.sha256(SECRET + val).hexdigest())


def check_secure_val(secure_val):
    """Check if value is secure"""
    if secure_val:
        val = secure_val.split('|')[0]
        if secure_val == make_secure_val(val):
            return val


def get_user(self):
    """Get current user by cookie"""
    user_cookie = self.request.cookies.get("user_id")
    if check_secure_val(user_cookie):
        user_id = user_cookie.split('|')[0]
        user = User.by_id(int(user_id))
        return user


class Handler(webapp2.RequestHandler):
    """Base Handler class"""

    def write(self, *a, **kw):
        """Write to webpage"""
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        """Render string"""
        my_template = JINJA_ENV.get_template(template)
        return my_template.render(params)

    def render(self, template, **kw):
        """Render html page"""
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        """Make a secure cookie"""
        cookie_val = make_secure_val(val)
        self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        """
        Get cookie val and return it if
        it's secure.
        """
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        """Set cookie when user logs in"""
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        """Remove cookie when user logs out"""
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')


class MainPage(Handler):
    """Main page"""
    def get(self):
        """
        Get blog posts and render
        them on the main page
        """
        blog_posts = db.GqlQuery("SELECT * FROM Blogpost ORDER BY created DESC")

        logged_in = False
        if get_user(self):
            logged_in = True

        self.render("mainpage.html", blog_posts=blog_posts, logged_in=logged_in)


class NewPost(Handler):
    """New post page"""
    def get(self):
        """Render new posts page"""
        self.render("newpost.html")

    def post(self):
        """
        Add new post to database if
        user is valid.
        """
        user = get_user(self)
        if user:
            subject = self.request.get("subject")
            content = self.request.get("content")
            writer = user.name
            if subject and content:
                post = Blogpost(subject=subject, content=content, writer=writer, likes=0, likers=[])
                post.put()

                self.redirect("/blog/%s" % post.key().id())
            else:
                self.render("newpost.html")
        else:
            self.redirect("/blog/login")


class EditPost(Handler):
    """Edit post page"""
    def get(self, blog_id):
        """
        Render edit page if
        user is valid.
        """
        my_blog = Blogpost.by_id(int(blog_id))

        user = get_user(self)
        if user and user.name == my_blog.writer:
            self.render("edit.html", post=my_blog)
        elif not user:
            self.redirect("/blog/login")
        else:
            self.redirect("/blog/%s" % blog_id)

    def post(self, blog_id):
        """
        Modify post and add it to
        database if user is valid.
        """
        my_blog = Blogpost.by_id(int(blog_id))

        user = get_user(self)
        if user and user.name == my_blog.writer:
            new_subject = self.request.get("subject")
            new_content = self.request.get("content")

            my_blog.subject = new_subject
            my_blog.content = new_content
            my_blog.put()

            self.redirect("/blog/%s" % blog_id)
        else:
            self.redirect("/blog/login")


class Permalink(Handler):
    """
    Permalink page for each
    individual post
    """
    def get(self, blog_id):
        """Render permalink page"""
        my_blog = Blogpost.by_id(int(blog_id))
        if my_blog:
            my_comments = Comment.gql("WHERE post=:1 ORDER BY created ASC", my_blog)
            self.render("permalink.html", post=my_blog, my_comments=my_comments)
        else:
            self.response.out.write("Ooops! Page does not exist!")

    def post(self, blog_id):
        """
        For commenting on posts.
        Add comment to database if user
        is valid.
        """
        my_blog = Blogpost.by_id(int(blog_id))
        comment_text = self.request.get("comment")
        if comment_text:
            user = get_user(self)
            if user:
                comment = Comment(writer=user.name,
                                  comment=comment_text,
                                  post=my_blog, likes=0,
                                  likers=[])
                comment.put()
            else:
                self.redirect("/blog/login")

        my_comments = Comment.gql("WHERE post=:1 ORDER BY created ASC", my_blog)

        self.render("permalink.html", post=my_blog, my_comments=my_comments)


class LikePost(Handler):
    """Handler for liking posts"""
    def get(self, blog_id):
        """
        Add like to current blog then
        redirect back to previous page.
        """
        my_blog = Blogpost.by_id(int(blog_id))

        user = get_user(self)
        if user and user.name not in my_blog.likers and user.name != my_blog.writer:
            my_blog.likes += 1
            my_blog.likers.append(user.name)
            my_blog.put()
            self.redirect("/blog/%s" % blog_id)

        elif not user:
            self.redirect("/blog/login")

        else:
            self.redirect("/blog/%s" % blog_id)


class DeletePost(Handler):
    """Handler for deleting posts"""
    def get(self, blog_id):
        """
        Delete post then redirect back
        to previous page.
        """
        my_blog = Blogpost.by_id(int(blog_id))
        user = get_user(self)

        if user and user.name == my_blog.writer:
            my_comments = Comment.gql("WHERE post=:1 ORDER BY created ASC", my_blog)
            db.delete(my_blog)
            db.delete(my_comments)
            self.redirect("/blog")

        elif not user:
            self.redirect("/blog/login")

        else:
            self.redirect("/blog/%s" % blog_id)


class EditComment(Handler):
    """Edit comment page"""
    def get(self, blog_id, comment_id):
        """Render edit comment page"""
        my_comment = Comment.by_id(int(comment_id))
        my_blog = Blogpost.by_id(int(blog_id))
        user = get_user(self)

        if user and my_comment.writer == user.name:
            self.render("editcomment.html", post=my_blog, comment=my_comment)
        elif not user:
            self.redirect("/blog/login")
        else:
            self.redirect("/blog/%s" % blog_id)


    def post(self, blog_id, comment_id):
        """Modify comment and add it to database"""
        my_comment = Comment.by_id(int(comment_id))
        new_comment = self.request.get("comment")
        my_comment.comment = new_comment
        my_comment.put()

        self.redirect("/blog/%s" % blog_id)


class DeleteComment(Handler):
    """Handler for deleting comment"""
    def get(self, blog_id, comment_id):
        """
        Delete comment and redirect
        back to previous page.
        """
        my_comment = Comment.by_id(int(comment_id))
        user = get_user(self)
        if user and my_comment.writer == user.name:
            db.delete(my_comment)
            self.redirect("/blog/%s" % blog_id)
        elif not user:
            self.redirect("/blog/login")
        else:
            self.redirect("/blog/%s" % blog_id)


class LikeComment(Handler):
    """Handler for liking comment"""
    def get(self, blog_id, comment_id):
        """
        Like comment and redirect
        back to previous page.
        """
        my_comment = Comment.by_id(int(comment_id))

        user = get_user(self)
        if user and user.name not in my_comment.likers and user.name != my_comment.writer:
            my_comment.likes += 1
            my_comment.likers.append(user.name)
            my_comment.put()
            self.redirect("/blog/%s" % blog_id)
        elif not user:
            self.redirect("/blog/login")
        else:
            self.redirect("/blog/%s" % blog_id)


class Signup(Handler):
    """Sign up page"""
    def get(self):
        """Render signup page"""
        self.render("user-signup.html")

    def post(self):
        """
        Add all info to database as a new user
        if information is valid.
        """
        self.username = self.request.get("username")
        self.password = self.request.get("password")
        self.verify = self.request.get("verify")
        self.email = self.request.get("email")

        if (valid_username(self.username) and valid_password(self.password) and
                valid_email(self.email) and self.password == self.verify):
            user = User.by_name(self.username)
            if user:
                username_error = "User already exists"
                self.render("user-signup.html", username_error=username_error)
            else:
                user = User.register(self.username, self.password, self.email)
                user.put()

                self.login(user)
                self.redirect('/blog/welcome')
        else:
            username_error = ""
            password_error = ""
            verify_error = ""
            email_error = ""

            if valid_username(self.username) is None:
                username_error = "Invalid username"
            if valid_password(self.password) is None:
                password_error = "Invalid password"
            if valid_email(self.email) is None:
                email_error = "Invalid email"
            if self.password != self.verify:
                verify_error = "Passwords do not match"
            self.render("user-signup.html", username=self.username,
                        email=self.email,
                        username_error=username_error,
                        password_error=password_error,
                        verify_error=verify_error,
                        email_error=email_error)


class Login(Handler):
    """Login page"""
    def get(self):
        """Render login page"""
        self.render("user-login.html")
    def post(self):
        """Log user in if info is valid"""
        self.username = self.request.get("username")
        self.password = self.request.get("password")

        user = User.by_name(self.username)
        if user:
            salt = user.pw_hash.split(',')[0]
            password_hash = make_pw_hash(self.username, self.password, salt)

            if user.pw_hash == password_hash:
                self.login(user)
                self.redirect('/blog/welcome')
            else:
                password_error = "Invalid password"
                self.render("user-login.html", password_error=password_error)
        else:
            username_error = "User does not exist"
            self.render("user-login.html", username_error=username_error)


class Logout(Handler):
    """Logout Handler"""
    def get(self):
        """Log out and redirect to login page"""
        if get_user(self):
            self.logout()
        self.redirect('/blog/login')


class Welcome(Handler):
    """Welcome page"""
    def get(self):
        """Render welcome page"""
        user = get_user(self)
        if user:
            self.render('welcome.html', username=user.name)
        else:
            self.redirect('/blog/signup')


class Blogpost(db.Model):
    """Blogpost model"""
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    writer = db.StringProperty(required=True)
    likes = db.IntegerProperty(required=True)
    likers = db.StringListProperty(required=True)

    @classmethod
    def by_id(cls, uid):
        """Get blogpost by id"""
        return Blogpost.get_by_id(uid)


class Comment(db.Model):
    """Comment model"""
    writer = db.StringProperty(required=True)
    comment = db.TextProperty(required=True)
    post = db.ReferenceProperty(Blogpost, collection_name='post_comments')
    created = db.DateTimeProperty(auto_now_add=True)
    likes = db.IntegerProperty(required=True)
    likers = db.StringListProperty(required=True)

    @classmethod
    def by_id(cls, uid):
        """Get comment by id"""
        return Comment.get_by_id(uid)


# User stuff
def make_salt():
    """
    Return and string of random
    letters to use as salt.
    """
    return ''.join(random.choice(string.letters) for x in xrange(5))


def make_pw_hash(name, password, salt=None):
    """
    Make password hash with
    username, password, and salt.
    """
    if not salt:
        salt = make_salt()
    my_hash = hashlib.sha256(name + password + salt).hexdigest()
    return salt + ',' + my_hash


def valid_pw(name, password, my_hash):
    """Return true if password is valid"""
    salt = my_hash.split(',')[0]
    return my_hash == make_pw_hash(name, password, salt)


class User(db.Model):
    """User model"""
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        """Get user by id"""
        return User.get_by_id(uid)

    @classmethod
    def by_name(cls, name):
        """Get user by name"""
        user = User.all().filter('name = ', name).get()
        return user

    @classmethod
    def register(cls, name, password, email=None):
        """Register user"""
        pw_hash = make_pw_hash(name, password)
        return User(name=name, pw_hash=pw_hash, email=email)


# clear_database()

# App
app = webapp2.WSGIApplication([('/blog', MainPage),
                               ('/blog/newpost', NewPost),
                               (r'/blog/(\d+)', Permalink),
                               (r'/blog/delete/(\d+)', DeletePost),
                               (r'/blog/edit/(\d+)', EditPost),
                               (r'/blog/like/(\d+)', LikePost),
                               (r'/blog/(\d+)/(\d+)', EditComment),
                               (r'/blog/(\d+)/like/(\d+)', LikeComment),
                               (r'/blog/(\d+)/delete/(\d+)', DeleteComment),
                               ('/blog/signup', Signup),
                               ('/blog/login', Login),
                               ('/blog/welcome', Welcome),
                               ('/blog/logout', Logout)], debug=True)

from google.appengine.ext import db  # pylint: disable=import-error

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


class Blogpost(db.Model):
    """Blogpost model"""
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    writer = db.ReferenceProperty(User, required=True)
    likes = db.IntegerProperty(required=True)
    likers = db.StringListProperty(required=True)

    @classmethod
    def by_id(cls, uid):
        """Get blogpost by id"""
        return Blogpost.get_by_id(uid)


class Comment(db.Model):
    """Comment model"""
    writer = db.ReferenceProperty(User, required=True)
    comment = db.TextProperty(required=True)
    post = db.ReferenceProperty(Blogpost, collection_name='post_comments')
    created = db.DateTimeProperty(auto_now_add=True)
    likes = db.IntegerProperty(required=True)
    likers = db.StringListProperty(required=True)

    @classmethod
    def by_id(cls, uid):
        """Get comment by id"""
        return Comment.get_by_id(uid)
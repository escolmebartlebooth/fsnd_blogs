import hmac
import hashlib
import random
import string

from google.appengine.ext import ndb

# for hmac on cookies - should be somewhere else
SECRET_KEY = "Fdh3nhUsLhy"


def make_secure_val(val):
    """ use hmac with secret key to create a secure cookie """
    return "{}|{}".format(val, hmac.new(SECRET_KEY, val).hexdigest())


def check_secure_val(secure_val):
    """ check that the current cookie is secure """
    val = secure_val.split("|")[0]
    if secure_val == make_secure_val(val):
        return val


def make_salt():
    """ make a 5 letter salt for password hashing """
    return ''.join(random.choice(string.letters) for x in xrange(5))


def make_pw_hash(name, pw, salt=None):
    """
    use sha256 with the salt and user name to create a secure password
    or take a passed salt to recreate a secure password for checking
    """
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)


def valid_pw(name, pw, h):
    """
    call the make_pw_hash with the salt stored with the password
    this checks whether user/password supplied matches that stored for the user
    """
    salt = h.split(",")[1]
    if make_pw_hash(name, pw, salt) == h:
        return True
    else:
        return False


class BlogUser(ndb.Model):
    """
    user who can login, write blog entries and comment/like other people's
    """
    username = ndb.StringProperty(required=True)
    pwd = ndb.StringProperty(required=True)
    email = ndb.StringProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add=True)

    @classmethod
    def by_id(cls, user_id):
        """ class method to return a user, if found, by ID """
        return cls.get_by_id(user_id)

    @classmethod
    def login(cls, username=None, password=None):
        """
            Check that the username and password is valid
            if so, return the User entity
        """

        # look up the username
        user_list = cls.query(cls.username == username).fetch(1)

        # check if user exists and password is valid against it's hash
        if user_list and valid_pw(username, password, user_list[0].pwd):
            return user_list[0]
        else:
            return None

    @classmethod
    def signup(cls, username=None, password=None, email=None):
        """
            method to register a new user
            assuming the user doesn't already exist
        """

        user = None

        # test if the username already exists
        user_list = cls.query(cls.username == username).fetch(1)
        if not user_list:
            # signup user if username does not exist create hashed password
            user = BlogUser(username=username,
                            pwd=make_pw_hash(username, password),
                            email=email).put()

        return user


class BlogComment(ndb.Model):
    """ blog comment for structured property as part of BlogPost """

    userkey = ndb.KeyProperty(kind=BlogUser, required=True)
    username = ndb.StringProperty(required=True)
    comment = ndb.TextProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add=True)
    updated = ndb.DateTimeProperty(auto_now=True)


class BlogPost(ndb.Model):
    """ Entity to store the blog entries made by owners """

    username = ndb.StringProperty(required=True)
    userkey = ndb.KeyProperty(kind=BlogUser, required=True)
    subject = ndb.StringProperty(required=True)
    blog = ndb.TextProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add=True)
    updated = ndb.DateTimeProperty(auto_now=True)
    likes = ndb.IntegerProperty()
    dislikes = ndb.IntegerProperty()
    comments = ndb.StructuredProperty(BlogComment, repeated=True)

    @classmethod
    def get_blogs(cls, n=1):
        """ return the top n blogs ordered by most recent update date """
        return cls.query().order(-cls.updated).fetch(n)

    @classmethod
    def by_id(cls, blog_id):
        """ return a specific blog entity by passing a blog id """
        return cls.get_by_id(blog_id)

    @classmethod
    def new_post(cls, user=None, subject="", posting=""):
        """ process a new post and return a post object """
        post = cls(username=user.username, userkey=user.key, subject=subject,
                   blog=posting, likes=0, dislikes=0, comments=[])
        return post.put()

    @classmethod
    def save_comment(cls, user=None, blog=None, comment_id=None,
                     comment=None):
        """ test the comment id and then update that comment """
        new_comment = BlogComment(userkey=user.key,
                                  username=user.username, comment=comment)

        # because using a structured property, create new list of comments
        new_comments = []
        x = 0
        # replace this comment defined by the index with the new version
        for item in blog.comments:
            if (comment_id != x):
                new_comments.append(item)
            else:
                new_comments.append(new_comment)
            x += 1
        blog.comments = new_comments
        return blog.put()


    # class method to delete a comment
    @classmethod
    def delete_comment(cls, blog=None, comment_id=None):
        """ remove the comment id from the list of comments """
        try:
            # is the comment id valid
            comment_id = int(comment_id)
            new_comments = []
            x = 0
            for item in blog.comments:
                if (comment_id != x):
                    new_comments.append(item)
                    x += 1
            blog.comments = new_comments
            return blog.put()
        except ValueError:
            return False


    # class method to add a comment
    @classmethod
    def add_comment(cls, user=None, blog=None, comment=None):
        """
            create a new comment and save it
        """
        try:
            blog_comment = BlogComment(userkey=user.key,
                                       username=user.username,
                                       comment=comment)
            # need to test if structure is present on blog
            if blog.comments:
                blog.comments.append(blog_comment)
            else:
                blog_comments = [blog_comment]
                blog.comments = blog_comments
            return blog.put()
        except ValueError:
            return False

    @classmethod
    def edit_blog(cls, blog=None, subject=None, posting=None):
        """ method to post the edit away """

        blog.subject = subject
        blog.blog = posting
        try:
            return blog.put()
        except:
            return False

    @classmethod
    def delete_blog(cls, blog=None):
        """ deletion process for a blog """
        try:
            # the blog is owned by the user so can delete
            blog.key.delete()
            return True
        except:
            return False

    @classmethod
    def like_blog(cls, user=None, blog=None, like_action=None):
        """ either like or dislike the blog and update the counts """
        try:
            if like_action:
                bloglike = BlogLike(userkey=user.key,
                                    blogkey=blog.key, like=True).put()
                if bloglike:
                    blog.likes += 1
                    blog.put()
            else:
                bloglike = BlogLike(userkey=user.key,
                                    blogkey=blog.key, like=False).put()
                if bloglike:
                    blog.dislikes += 1
                    blog.put()
            return True
        except:
            return False


class BlogLike(ndb.Model):
    """ referenced entity to manage like / dislike of blog post """

    userkey = ndb.KeyProperty(kind=BlogUser, required=True)
    blogkey = ndb.KeyProperty(kind=BlogPost, required=True)
    like = ndb.BooleanProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add=True)

    @classmethod
    def like_exists(cls, user=None, blog=None):
        """ return a match if a user has liked/disliked a blog """
        return cls.query(cls.blogkey == blog.key,
                         cls.userkey == user.key).fetch(1)
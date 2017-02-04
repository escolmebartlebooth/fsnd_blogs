# imports start
import os
import jinja2
import webapp2
import re
import hmac
import hashlib
import random
import string

from google.appengine.ext import ndb

# end imports

# create jinja2 environment
TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), 'templates')
JINJA_ENV = jinja2.Environment(loader=jinja2.FileSystemLoader(TEMPLATE_DIR),
                               autoescape=True)

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
        e = {}
        try:
            # is the comment id ok
            comment_id = int(comment_id)
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
            blog.put()
            e['postcomment'] = False
        except ValueError:
            e['error'] = 'Bad blog id'

        return e

    @classmethod
    def user_owns_comment(cls, user, blog, comment_id):
        """ method checks if the user owns the comment passed """
        try:
            comment_id = int(comment_id)
            if (user.key == blog.comments[comment_id].userkey):
                # the user doesn't own the comment so error
                return True
            else:
                return False
        except:
            # bad comment id
            return False

    # class method to delete a comment
    @classmethod
    def delete_comment(cls, blog=None, comment_id=None):
        """ remove the comment id from the list of comments """
        e = {}
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
                blog.put()
                e['postcomment'] = False
        except ValueError:
            e['error'] = 'Bad comment id'

        return e

    # class method to add a comment
    @classmethod
    def add_comment(cls, user=None, blog=None, comment=None):
        """
            create a new comment and save it
        """
        e = {}
        try:
            blog_comment = BlogComment(userkey=user.key,
                                       username=user.username,
                                       comment=comment)
            # need to test if structure is present on blog
            if blog.comments:
                blog.comments.append(blog_comment)
                blog.put()
            else:
                blog_comments = [blog_comment]
                blog.comments = blog_comments
                blog.put()
            e['postcomment'] = False
        except ValueError:
            e['error'] = 'something went wrong'

        return e

    @classmethod
    def edit_blog(cls, blog=None, subject=None, posting=None):
        """ method to post the edit away """

        blog.subject = subject
        blog.blog = posting
        try:
            blog.put()
            return True
        except:
            return False

    @classmethod
    def user_owns_blog(cls, user=None, blog=None):
        """ checks if the user owns the blog """
        if (user.key == blog.userkey):
            return True

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


class Handler(webapp2.RequestHandler):
    """ a baseic handler to render pages and handle events """

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = JINJA_ENV.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, user=self.user, **kw))

    def login(self, username, password):
        """
            try to login
            if successful write a secure cookie to the browser
        """

        user = None
        e = {}

        # if the username isn't blank, continue, else fail
        if username:
            # as the User Entity if the username and password are valid
            user = BlogUser.login(username, password)

        # if the user is good, then set a cookie on the site
        if user:
            self.set_secure_cookie('user_id', str(user.key.id()))
        else:
            e = {'error': 'invalid login'}

        return (user, e)

    def signup(self, username, password, verify, email):
        """
            test that values are valid
            then register the user and then login
        """

        # create checkers
        user_re = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
        password_re = re.compile(r"^.{3,20}$")
        email_re = re.compile(r"^[\S]+@[\S]+.[\S]+$")

        user = None
        e = {}

        # is the username a valid style?
        if not (username and user_re.match(username)):
            e['username'] = 'invalid username'

        # is the password a valid style and does it match the verify?
        if not (password and user_re.match(password)):
            e['password'] = 'invalid password'
        elif (password != verify):
            e['verify'] = 'passwords must match'

        # if provided, is the email a valid style?
        if (email and not email_re.match(email)):
            e['email'] = 'invalid email'

        # if all looks well, register the user
        if not e:
            user = BlogUser.signup(username, password, email)
            if user:
                # if registered successfully, log the user in
                self.set_secure_cookie('user_id', str(user.id()))
            else:
                e['username'] = 'username exists'

        return (user, e)

    def logout(self):
        """ clear the user_id cookie if the User is set """

        if self.user:
            self.response.headers.add_header('Set-Cookie', "user_id=; Path=/")
        self.redirect("/blog")

    def delete_blog(self, user=None, blog=None):
        """ check that the user owns the blog and if so delete it """
        if not user:
            return {'error': 'you must be logged in'}
        elif not BlogPost.user_owns_blog(user, blog):
            return {'error': 'you do not own this blog'}
        elif not BlogPost.delete_blog(blog):
            return {'error': 'deletion failed'}
        else:
            return None

    def like_blog(self, user=None, blog=None, like_action=None):
        """
            check that user doesn't own blog and that blog hasn't been liked
            then either like or dislike as requested
        """
        if not user:
            return {'error': 'you must be logged in'}
        elif BlogPost.user_owns_blog(user, blog):
            return {'error': 'you own this blog so cannot like/dislike it'}
        elif BlogLike.like_exists(user, blog):
            return {'error': 'you cannot dis/like this blog more than once'}
        elif not BlogPost.like_blog(user, blog, like_action):
            return {'error': 'like/dislike failed'}
        else:
            return None

    def set_secure_cookie(self, name, val):
        """
            create a secure cookie from the passed value
            and store against the name
        """

        cookie_val = make_secure_val(val)
        self.response.headers.add_header('Set-Cookie',
                                         "{}={}; Path=/".format(name,
                                                                cookie_val))

    def read_secure_cookie(self, name):
        """ read the cookie from the browser """
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def initialize(self, *a, **kw):
        """ used to access the user cookie and store against the handler """

        webapp2.RequestHandler.initialize(self, *a, **kw)
        user_id = self.read_secure_cookie('user_id')
        self.user = user_id and BlogUser.by_id(int(user_id))


class blog(Handler):
    """ handler for the main app page to display and edit blogs """

    def render_blog(self, **kw):
        self.render("blog.html", **kw)

    def get(self):
        """ get the ten most recent blog entries and render the page """
        blogs = BlogPost.get_blogs(10)
        self.render_blog(pagetitle="welcome to bartlebooth blogs",
                         blogs=blogs, e=None, viewpost=False)

    def post(self):
        """ process the multiple forms that are on the blog main page """

        # get the user and blog id from the form entries
        user_id = self.read_secure_cookie("user_id")
        blog_id = self.request.get('blog_id')
        e = {}
        try:
            # is user valid
            user = BlogUser.by_id(int(user_id))
            try:
                # the blog and user from the ids
                blog = BlogPost.by_id(int(blog_id))

                # form value is DELETE
                if self.request.get('blogdelete'):
                    # pass deletion to a common handler
                    e = self.delete_blog(user, blog)
                # form value is LIKE
                elif self.request.get('like'):
                    # try to LIKE the post
                    e = self.like_blog(user, blog, True)
                # form value is DISLIKE
                elif self.request.get('dislike'):
                    # try to DISLIKE the post
                    e = self.like_blog(user, blog, False)
            except ValueError:
                e = {'error': 'Bad Blog Id'}
        except ValueError:
                e = {'error': 'Please Login'}

        blogs = BlogPost.get_blogs(10)
        self.render_blog(pagetitle="welcome to bartlebooth blogs",
                         blogs=blogs, e=e)


class blogedit(Handler):
    """ Handle updates to blog posts """

    def render_editpost(self, **kw):
        self.render("editpost.html", **kw)

    def get(self):
        """
            get the blog from the query parameter
            check user owns the blog
        """

        e = {}
        blog = None
        if self.request.get('b'):
            blog_id = self.request.get('b')
            user_id = self.read_secure_cookie("user_id")
        try:
            # is the user valid
            user = BlogUser.by_id(int(user_id))
            try:
                # test the blog is valid
                blog = BlogPost.by_id(int(blog_id))
                # does the user own the blog
                if not BlogPost.user_owns_blog(user, blog):
                    e["error"] = "you cannot edit as this is not your post"
            except ValueError:
                e["error"] = "The blog id is invalid"
        except (TypeError, ValueError):
                e["error"] = "Please Login"

        # render the edit form
        self.render_editpost(pagetitle="edit post", blog=blog, e=e)

    def post(self):
        """
            Check the user, blog and subject/comment entries
            then post or fail the edit
        """

        # get the form values from the edit post
        blog_id = self.request.get("blog_id")
        user_id = self.read_secure_cookie("user_id")
        subject = self.request.get("subject")
        posting = self.request.get("posting")
        e = {}
        blog = None

        try:
            # test the user
            user = BlogUser.by_id(int(user_id))
            try:
                # test blog
                blog = BlogPost.by_id(int(blog_id))
                # see if the user owns the blog
                if not BlogPost.user_owns_blog(user, blog):
                    e['error'] = 'You do not own this blog'
                elif not (subject and posting):
                    # set a post error instead of an error to show save button
                    e['posterror'] = 'subject and posting must not be empty'
                else:
                    # blog is owned by the user so can edit and entry is fine
                    BlogPost.edit_blog(blog=blog, subject=subject,
                                       posting=posting)
            except ValueError:
                e['error'] = 'Bad blog id'
        except (TypeError, ValueError):
            e['error'] = 'you must login to do this'

        if not e:
            # no errors so show view post
            self.redirect("/blog/view?b={}".format(blog_id))
        else:
            # if errors, render edit post page with errors
            self.render_editpost(pagetitle="edit post",
                                 blog=blog, e=e)


class logout(Handler):
    """
        Handle a GET to the /blog/logout page
        pass control to Base Handler
    """

    def get(self):
        self.logout()


class signup(Handler):
    """
        Handler to process a sign up request
        either log the user in or error
    """

    def render_signup(self, **kw):
        self.render("signup.html", **kw)

    def get(self):
        """ pass to handler function """
        self.render_signup(pagetitle="signup to bartlebooth blogs",
                           items=None, e=None)

    def post(self):
        """
            capture form input
            then pass to base handler to verify signup
        """

        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        # check if user signup is ok
        user, e = self.signup(username, password, verify, email)

        # if ok, show the welcome page to the new user and log the user in
        if user:
            self.redirect("/blog/welcome")
        else:
            # else show an error set on the signup page
            items = {'username': username, 'email': email}
            self.render_signup(pagetitle="signup to bartlebooth blogs",
                               items=items, e=e)


class login(Handler):
    """
        Handler which renders a login page
        then processes the input to log a user in
    """

    def render_login(self, **kw):
        self.render("login.html", **kw)

    def get(self):
        self.render_login(pagetitle="login to bartlebooth blogs",
                          items=None, e=None)

    def post(self):
        """
            Process the Login form input
            either log the user in or report errors
        """

        # capture form values
        username = self.request.get('username')
        password = self.request.get('password')

        # check if user valid
        user, e = self.login(username, password)

        # if valid, show the welcome page and login the user
        if user:
            self.redirect("/blog/welcome")
        else:
            # if not valid return error
            items = {'username': username}
            self.render_login(pagetitle="login to bartlebooth blogs",
                              items=items, e=e)


class welcome(Handler):
    """ Handler to display a welcome page if a user is logged in """
    def render_welcome(self, **kw):
        self.render("welcome.html", **kw)

    def get(self):
        """
            check if valid user and render page
            otherwise direct to login
        """

        if self.user:
            # pass to handler function
            page_title = "welcome to bb blogs {}".format(self.user.username)
            self.render_welcome(pagetitle=page_title)
        else:
            # pass to login page if not a valid user
            self.redirect("/blog/login")


class newpost(Handler):
    """
        Handles authentication and rendering of new post page
        Handles the processing of the new post itself
    """

    def render_newpost(self, **kw):
        self.render("newpost.html", **kw)

    def get(self):
        """
            check if valid user and render page
            otherwise direct to login
        """
        user = self.read_secure_cookie("user_id")
        if user:
            # the user is valid so render the new post page
            self.render_newpost(pagetitle="new post", items=None, e=None)
        else:
            # the user isn't valid so pass to login page
            self.redirect("/blog/login")

    def post(self):
        """
        Captures the new post parameters
        Checks for validity and creates the new post
        """

        # get input and logged on user
        subject = self.request.get('subject')
        posting = self.request.get('posting')
        user = self.read_secure_cookie("user_id")
        e = {}

        if not self.user:
            # if the user isn't valid, go to the login page
            self.redirect("/blog/login")
        elif not subject or not posting:
            # if either subject or post is empty, raise an error
            e['error'] = "Subject and Post cannot be blank"
        else:
            post = BlogPost.new_post(BlogUser.get_by_id(int(user)),
                                     subject, posting)
            if not post:
                e['error'] = 'Error on post'
        if e:
            # if error dictionary has entries, render form with the errors
            items = {'subject': subject, 'posting': posting}
            self.render_newpost(pagetitle="new post", items=items, e=e)
        else:
            # if ok, show the view page for the blog entry
            self.redirect("/blog/view?b={}".format(str(post.id())))


class viewpost(Handler):
    """ handler to display an individual blog entry """

    def render_viewpost(self, **kw):
        self.render("viewpost.html", **kw)

    def get(self):
        """
            get the blog_id on the query string and test it's validity
            if ok, show the blog, if not sliently redirect to the /blog page
        """
        e = {}
        blog_id = self.request.get('b')
        try:
            # fetch the blog entity then render the view page
            blog = BlogPost.by_id(int(blog_id))
            self.render_viewpost(pagetitle="post: {}".format(blog.subject),
                                 blog=blog, e=e, viewpost=True)
        except ValueError:
            # if an error getting the blog redirect to the blog page
            self.redirect("/blog")

    def post(self):
        """ handler for the multiple forms on the view page """

        # get the user and blog id
        user_id = self.read_secure_cookie("user_id")
        blog_id = self.request.get('blog_id')
        e = {}

        try:
            # is the user valid?
            user = BlogUser.by_id(int(user_id))
            try:
                # get the blog entry and user
                blog = BlogPost.by_id(int(blog_id))

                # form value is DELETE
                if self.request.get('blogdelete'):
                    # pass deletion to a common handler
                    e = self.delete_blog(user, blog)
                # form value is LIKE
                elif self.request.get('like'):
                    e = self.like_blog(user, blog, True)
                # form value is DISLIKE
                elif self.request.get('dislike'):
                    e = self.like_blog(user, blog, False)
                # form value is POST COMMENT
                elif self.request.get('postcomment'):
                    if BlogPost.user_owns_blog(user, blog):
                        e['error'] = 'You cannot comment on this blog'
                    else:
                        e['postcomment'] = True
                # form value is BLOG CANCEL
                elif self.request.get('blogcancel'):
                        e['postcomment'] = False
                # form value is ADD COMMENT
                elif self.request.get('addcomment'):
                    comment = self.request.get('comment')
                    if comment:
                        # comment isn't empty
                        if BlogPost.user_owns_blog(user, blog):
                            e['error'] = 'You cannot comment on this blog'
                        else:
                            # save the comment
                            e = BlogPost.add_comment(user, blog, comment)
                    else:
                        e['error'] = 'comment cannot be blank'
                # form value is DELETE COMMENT
                elif self.request.get('deletecomment'):
                    comment_id = self.request.get('comment_id')
                    if BlogPost.user_owns_comment(user, blog, comment_id):
                        e = BlogPost.delete_comment(blog, comment_id)
                    else:
                        e['error'] = 'You do not own this comment'
                # form value is EDIT COMMENT - EDIT
                elif self.request.get('editcomment'):
                    comment_id = self.request.get('comment_id')
                    if BlogPost.user_owns_comment(user, blog, comment_id):
                        e['editcomment'] = comment_id
                    else:
                        e['error'] = 'you cannot edit this comment'
                # form value is EDIT COMMENT - CANCEL
                elif self.request.get('editcancelcomment'):
                    e['postcomment'] = False
                # form value is EDIT COMMENT - SAVE
                elif self.request.get('editsavecomment'):
                    comment_id = self.request.get('comment_id')
                    comment = self.request.get('comment')
                    if comment:
                        # comment isn't empty
                        if not BlogPost.user_owns_comment(user, blog,
                                                          comment_id):
                            e['error'] = 'You cannot edit this comment'
                        else:
                            # save the comment
                            e = BlogPost.save_comment(user,
                                                      blog,
                                                      comment_id, comment)
                    else:
                        e['error'] = 'comment cannot be blank'
            except ValueError:
                e = {'error': 'Bad Blog Id'}
        except (TypeError, ValueError):
            e = {'error': 'Please Login'}
        # if it was deleted render the blog form
        if not e:
            self.redirect("/blog")
        else:
            # otherwise re-render the view post
            blog = BlogPost.by_id(int(blog_id))
            self.render_viewpost(pagetitle="post: {}".format(blog.subject),
                                 blog=blog, e=e, viewpost=True)

# register page handlers
app = webapp2.WSGIApplication([
    ('/blog', blog),
    ('/blog/logout', logout),
    ('/blog/login', login),
    ('/blog/signup', signup),
    ('/blog/welcome', welcome),
    ('/blog/new', newpost),
    ('/blog/view', viewpost),
    ('/blog/edit', blogedit)
    ],
    debug=False)

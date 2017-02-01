# imports start
import os
import jinja2
import webapp2
import re
import hmac
import hashlib
import random
import string

import logging

from google.appengine.ext import ndb

# end imports

# create jinja2 environment
TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), 'templates')
JINJA_ENV = jinja2.Environment(loader = jinja2.FileSystemLoader(TEMPLATE_DIR),
    autoescape=True)

# for hmac on cookies - should be somewhere else
SECRET_KEY = "Fdh3nhUsLhy"

# cookie cutters
# use hmac with secret key to create a secure cookie
def make_secure_val(val):
    return "{}|{}".format(val, hmac.new(SECRET_KEY,val).hexdigest())

# check that the current cookie is secure
def check_secure_val(secure_val):
    val = secure_val.split("|")[0]
    if secure_val == make_secure_val(val):
        return val

# pwd functions
# make a 5 letter salt for password hashing
def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

# use sha256 with the salt and user name to create a secure password
# or take a passed salt to recreate a secure password for checking
def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)

# call the make_pw_hash with the salt stored with the password
# this checks whether user/password supplied matches that stored for the user
def valid_pw(name, pw, h):
    # TO DO: add try / except for bad passwords...
    salt = h.split(",")[1]
    if make_pw_hash(name, pw, salt) == h:
        return True
    else:
        return False

# google data store entities
# user who can login, write blog entries and comment/like other people's
class BlogUser(ndb.Model):
    username = ndb.StringProperty(required=True)
    pwd = ndb.StringProperty(required=True)
    email = ndb.StringProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add=True)

    # class method to return a user, if found, by ID
    @classmethod
    def by_id(cls,user_id):
        return cls.get_by_id(user_id)

    @classmethod
    def login(cls,username=None,password=None):
        """ Check that the username and password is valid and if so, return the User entity """

        # look up the username
        user_list = cls.query(cls.username == username).fetch(1)

        # check if the user exists and the provided password is valid against it's hash
        if user_list and valid_pw(username,password,user_list[0].pwd):
            return user_list[0]
        else:
            return None

    # class method to signup a new user
    @classmethod
    def signup(cls,username=None,password=None,email=None):
        """ method to register a new user assuming the user doesn't already exist """

        user = None

        # test if the username already exists
        user_list = cls.query(cls.username == username).fetch(1)
        if not user_list:
            # signup user if the username does not exist and create a hashed password
            user = BlogUser(username=username,pwd=make_pw_hash(username,password),
                email=email).put()

        return user

# blog comment for structured property as part of BlogPost
class BlogComment(ndb.Model):
    userkey = ndb.KeyProperty(kind=BlogUser, required=True)
    username = ndb.StringProperty(required=True)
    comment = ndb.TextProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add=True)
    updated = ndb.DateTimeProperty(auto_now=True)

class BlogPost(ndb.Model):
    """ Entity to store the blog entries made by owners """

    username = ndb.StringProperty(required=True)
    userkey = ndb.KeyProperty(kind=BlogUser,required=True)
    subject = ndb.StringProperty(required=True)
    blog    = ndb.TextProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add=True)
    updated = ndb.DateTimeProperty(auto_now=True)
    likes = ndb.IntegerProperty()
    dislikes = ndb.IntegerProperty()
    comments = ndb.StructuredProperty(BlogComment,repeated=True)

    @classmethod
    def get_blogs(cls,n=1):
        """ return the top n blogs ordered by most recent update date """
        return cls.query().order(-cls.updated).fetch(n)

    @classmethod
    def by_id(cls,blog_id):
        """ return a specific blog entity by passing a blog id """
        return cls.get_by_id(blog_id)

    @classmethod
    def new_post(cls,user=None,subject="",posting=""):
        """ process a new post and return a post object """
        post=cls(username=user.username,userkey=user.key,subject=subject,
                blog=posting,likes=0,dislikes=0,comments=[])
        return post.put()

    # class method to store an edited comment
    @classmethod
    def edit_comment(cls,user_id=None,blog_id=None,comment_id=None,comment=None):
        status = True
        e = {}
        blog = None
        # is user logged in? - assume user_id result of read_secure_cookie...
        if not user_id:
            status = False
            e['error'] = 'you must login to do this'
            # see if the blog_id sent is valid before returning not logged in error
            try:
                blog = BlogPost.by_id(int(blog_id))
            except ValueError:
                e['error'] = 'Bad blog id'
        else:
            try:
                # the blog user is valid, now see if the user has permissions to edit
                comment_id = int(comment_id)
                user = BlogUser.by_id(int(user_id))
                blog = BlogPost.by_id(int(blog_id))

                # is the user the same one who created the comment
                if (user.key != blog.comments[comment_id].userkey):
                    # NO comment isn't this user's
                    status = False
                    e['error'] = 'you cannot do this as you do not own this comment'
                elif not comment:
                    # user ok but comment is empty
                    status = False
                    e['error'] = 'comment cannot be empty'
                else:
                    # user, blog, permissions are ok so save the edit
                    new_comment = BlogComment(userkey=user.key,
                            username=user.username, comment=comment)
                    new_comments = []
                    x = 0
                    # because using a structured property, create new list of comments
                    # replace this comment - defined by the index - with the new version
                    for item in blog.comments:
                        if (comment_id != x):
                            new_comments.append(item)
                        else:
                            new_comments.append(new_comment)
                        x += 1
                    blog.comments = new_comments
                    blog.put()
            except ValueError:
                status = False
                e['error'] = 'Bad blog id'

        return (status, blog, e)

    # class method to see if a comment can be edited
    @classmethod
    def can_edit_comment(cls,user_id=None,blog_id=None,comment_id=None):
        status = True
        e = {}
        blog = None
        # is user logged in
        if not user_id:
            status = False
            e['error'] = 'you must login to do this'
            try:
                blog = BlogPost.by_id(int(blog_id))
            except ValueError:
                e['error'] = 'Bad blog id'
        else:
            try:
                # get the user object and the blog object
                comment_id = int(comment_id)
                user = BlogUser.by_id(int(user_id))
                blog = BlogPost.by_id(int(blog_id))
                # check if the user owns the comment and error if they do not
                if (user.key != blog.comments[comment_id].userkey):
                    # comment is not owned by the user, so error
                    status = False
                    e['error'] = 'you cannot do this as you do not own this comment'
                else:
                    # user is logged in and owns the comment so edit
                    e['editcomment'] = str(comment_id)
            except ValueError:
                status = False
                e['error'] = 'Bad blog id'

        return (status, blog, e)

    # class method to delete a comment
    @classmethod
    def delete_comment(cls,user_id=None,blog_id=None,comment_id=None):
        status = True
        e = {}
        blog = None
        # is user logged in
        if not user_id:
            status = False
            e['error'] = 'you must login to do this'
            try:
                blog = BlogPost.by_id(int(blog_id))
            except ValueError:
                e['error'] = 'Bad blog id'
        else:
            try:
                # is the comment owned by the user
                comment_id = int(comment_id)
                user = BlogUser.by_id(int(user_id))
                blog = BlogPost.by_id(int(blog_id))
                if (user.key != blog.comments[comment_id].userkey):
                    # the user doesn't own the comment so error
                    status = False
                    e['error'] = 'you cannot do this as you do not own this comment'
                else:
                    # the user does own the comment and is logged in so can delete
                    # deletion achieved by reposting all comments except the one being deleted
                    new_comments = []
                    x = 0
                    for item in blog.comments:
                        if (comment_id != x):
                            new_comments.append(item)
                        x += 1
                    blog.comments = new_comments
                    blog.put()
            except ValueError:
                status = False
                e['error'] = 'Bad blog id'

        return (status, blog, e)

    # class method to add a comment
    @classmethod
    def add_comment(cls,user_id=None,blog_id=None,comment=None):
        status = True
        e = {}
        blog = None
        # is user logged in
        if not user_id:
            status = False
            e['error'] = 'you must login to do this'
            try:
                blog = BlogPost.by_id(int(blog_id))
            except ValueError:
                e['error'] = 'Bad blog id'
        else:
            try:
                # the commentor should not be the owner of the blog
                user = BlogUser.by_id(int(user_id))
                blog = BlogPost.by_id(int(blog_id))
                if (user.key == blog.userkey):
                    # blog is owned by user so cannot comment
                    status = False
                    e['error'] = 'you cannot do this as you own this post'
                else:
                    # can post, so create a new comment and store it against the blog
                    # comment cannot be blank
                    if comment:
                        # add comment
                        blog_comment = BlogComment(userkey=user.key,
                            username=user.username, comment=comment)
                        # need to test if structure is present on blog
                        if blog.comments:
                            blog.comments.append(blog_comment)
                            blog.put()
                        else:
                            blog_comments = [blog_comment]
                            blog.comments = blog_comments
                            blog.put()
                    else:
                        # comment is blank so error
                        status = False
                        e['error'] = 'Comment must not be empty'
            except ValueError:
                status = False
                e['error'] = 'Bad blog id'

        return (status, blog, e)

    # class method to check if user can comment
    @classmethod
    def can_comment(cls,user_id=None,blog_id=None):
        status = True
        e = {}
        blog = None
        # is user logged in
        if not user_id:
            status = False
            e['error'] = 'you must login to do this'
            try:
                blog = BlogPost.by_id(int(blog_id))
            except ValueError:
                e['error'] = 'Bad blog id'
        else:
            try:
                # is blog owned by commentor
                user = BlogUser.by_id(int(user_id))
                blog = BlogPost.by_id(int(blog_id))
                if (user.key == blog.userkey):
                    # user owns this blog so can't comment
                    status = False
                    e['error'] = 'you cannot do this as you do not own this post'
                else:
                    # user can comment
                    e['postcomment'] = 'can comment'
            except ValueError:
                status = False
                e['error'] = 'Bad blog id'

        return (status, blog, e)

    @classmethod
    def edit_blog(cls,blog=None,subject=None,posting=None):
        """ method to post the edit away """

        blog.subject = subject
        blog.blog = posting
        try:
            blog.put()
            return True
        except:
            return False

    @classmethod
    def user_owns_blog(cls,user=None,blog=None):
        """ checks if the user owns the blog """
        if (user.key == blog.userkey):
            return True

    @classmethod
    def delete_blog(cls,blog=None):
        """ deletion process for a blog """
        try:
            # the blog is owned by the user so can delete
            blog.key.delete()
            return True
        except:
            return False

    # class method to like or dislike a post
    @classmethod
    def like_blog(cls,user=None,blog=None,like_action=None):
        """ either like or dislike the blog and update the counts """
        try:
            if like_action:
                bloglike = BlogLike(userkey=user.key,
                    blogkey=blog.key,like=True).put()
                if bloglike:
                    blog.likes += 1
                    blog.put()
            else:
                bloglike = BlogLike(userkey=user.key,
                    blogkey=blog.key,like=False).put()
                if bloglike:
                    blog.dislikes += 1
                    blog.put()
            return True
        except:
            return False

# blog like structure
class BlogLike(ndb.Model):
    userkey = ndb.KeyProperty(kind=BlogUser, required=True)
    blogkey = ndb.KeyProperty(kind=BlogPost,required=True)
    like = ndb.BooleanProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add=True)

    # checker to see if a like / dislike has been saved by a user already
    @classmethod
    def like_exists(cls,user=None,blog=None):
        return cls.query(cls.blogkey==blog.key,cls.userkey==user.key).fetch(1)

# base handler for a request
class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a,**kw)

    def render_str(self, template, **params):
        t = JINJA_ENV.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, user=self.user, **kw))

    def login(self, username, password):
        """ try to login and if successful write a secure cookie to the browser """

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
            e = {'error':'invalid login'}

        return (user, e)

    def signup(self, username, password, verify, email):
        """ test that values are valid and then register the user and then login """

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
        """ Clear the user_id cookie if the User is set on the page calling /logout"""
        if self.user:
            self.response.headers.add_header('Set-Cookie',"user_id=; Path=/")
        self.redirect("/blog")

    def delete_blog(self, user=None, blog=None):
        """ check that the user owns the blog and if so delete it """
        if not user:
            return {'error':'you must be logged in'}
        elif not BlogPost.user_owns_blog(user,blog):
            return {'error':'you do not own this blog'}
        elif not BlogPost.delete_blog(blog):
            return {'error':'deletion failed'}
        else:
            return None

    def like_blog(self, user=None, blog=None, like_action=None):
        """
            check that user doesn't own blog and that blog hasn't been liked
            then either like or dislike as requested
        """
        if not user:
            return {'error':'you must be logged in'}
        elif BlogPost.user_owns_blog(user,blog):
            return {'error':'you own this blog so cannot like/dislike it'}
        elif BlogLike.like_exists(user,blog):
            return {'error':'you cannot like/dislike this blog more than once'}
        elif not BlogPost.like_blog(user,blog,like_action):
            return {'error':'like/dislike failed'}
        else:
            return None

    def set_secure_cookie(self, name, val):
        # create a secure cookie from the passed value and store against the name
        cookie_val = make_secure_val(val)
        self.response.headers.add_header('Set-Cookie',"{}={}; Path=/".format(name,
            cookie_val))

    def read_secure_cookie(self, name):
        # read the cookie from the browser
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def initialize(self, *a, **kw):
        # used to access the user cookie and store against the handler
        webapp2.RequestHandler.initialize(self, *a, **kw)
        user_id = self.read_secure_cookie('user_id')
        self.user = user_id and BlogUser.by_id(int(user_id))

class blog(Handler):
    """ handler for the main app page to display and edit blogs """

    def render_blog(self,**kw):
        self.render("blog.html",**kw)

    def get(self):
        """ get the ten most recent blog entries and render the page """
        blogs = BlogPost.get_blogs(10)
        self.render_blog(pagetitle="welcome to bartlebooth blogs",blogs=blogs,e=None,viewpost=False)

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
                    # try to LIKE the post - if this isn't possible an error will be returned
                    e = self.like_blog(user,blog,True)
                # form value is DISLIKE
                elif self.request.get('dislike'):
                    # try to DISLIKE the post - if this isn't possible an error will be returned
                    e = self.like_blog(user,blog,False)
            except ValueError:
                e = {'error':'Bad Blog Id'}
        except ValueError:
                e = {'error':'Please Login'}

        blogs = BlogPost.get_blogs(10)
        self.render_blog(pagetitle="welcome to bartlebooth blogs",
                blogs=blogs,e=e)

class blogedit(Handler):
    """ Handle updates to blog posts """

    def render_editpost(self,**kw):
        self.render("editpost.html",**kw)

    def get(self):
        """ get the blog from the query parameter and check user owns the blog """
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
                if not BlogPost.user_owns_blog(user,blog):
                    e["error"] = "you cannot edit as this is not your post"
            except ValueError:
                e["error"] = "The blog id is invalid"
        except (TypeError, ValueError):
                e["error"] = "Please Login"

        # render the edit form - if an error occurred, the form will stop the SAVE button being rendered
        self.render_editpost(pagetitle="edit post",blog=blog,e=e)

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
                if not BlogPost.user_owns_blog(user,blog):
                    e['error'] = 'You do not own this blog'
                elif not (subject and posting):
                    # set a post error instead of an error to show save button
                    e['posterror'] = 'the subject and posting must not be empty'
                else:
                    # blog is owned by the user so can edit and entry is fine
                    BlogPost.edit_blog(blog=blog,subject=subject,posting=posting)
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
                    blog=blog,e=e)

class logout(Handler):
    """ Handle a GET to the /blog/logout page pass control to Base Handler """
    def get(self):
        self.logout()

# handler to sign up a new user
class signup(Handler):
    """ Handler to process a sign up request and either log the user in or error """
    def render_signup(self,**kw):
        self.render("signup.html",**kw)

    def get(self):
        # pass to handler function
        self.render_signup(pagetitle="signup to bartlebooth blogs",items=None,e=None)

    def post(self):
        """ capture form input and then pass to base handler to verify signup """
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        # check if user signup is ok
        user, e = self.signup(username,password,verify,email)

        # if ok, show the welcome page to the new user and log the user in
        if user:
            self.redirect("/blog/welcome")
        else:
            # else show an error set on the signup page
            items = {'username':username,'email':email}
            self.render_signup(pagetitle="signup to bartlebooth blogs",items=items,e=e)

class login(Handler):
    """ Handler which renders a login page and then processes the input to log a user in"""

    def render_login(self,**kw):
        self.render("login.html",**kw)

    def get(self):
        self.render_login(pagetitle="login to bartlebooth blogs",items=None,e=None)

    def post(self):
        """ Process the Login form input and either log the user in or report errors """

        # capture form values
        username = self.request.get('username')
        password = self.request.get('password')

        # check if user valid
        user, e = self.login(username,password)

        # if valid, show the welcome page and login the user
        if user:
            self.redirect("/blog/welcome")
        else:
            # if not valid return error
            items = {'username':username}
            self.render_login(pagetitle="login to bartlebooth blogs",items=items,e=e)

class welcome(Handler):
    """ Handler to display a welcome page if a user is logged in """
    def render_welcome(self,**kw):
        self.render("welcome.html",**kw)

    def get(self):
        # check if valid user
        if self.user:
            # pass to handler function
            self.render_welcome(pagetitle="welcome to bartlebooth blogs {}".format(self.user.username))
        else:
            # pass to login page if not a valid user
            self.redirect("/blog/login")

class newpost(Handler):
    """
        Handles authentication and rendering of new post page
        Handles the processing of the new post itself
    """

    def render_newpost(self,**kw):
        self.render("newpost.html",**kw)

    def get(self):
        # check if a valid user is logged in
        user = self.read_secure_cookie("user_id")
        if user:
            # the user is valid so render the new post page
            self.render_newpost(pagetitle="new post",items=None,e=None)
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
            post = BlogPost.new_post(BlogUser.get_by_id(int(user))
                ,subject,posting)
            if not post:
                e['error'] = 'Error on post'
        if e:
            # if the error dictionary has entries, render the form with the errors
            items = {'subject':subject,'posting':posting}
            self.render_newpost(pagetitle="new post",items=items,e=e)
        else:
            # if ok, show the view page for the blog entry
            self.redirect("/blog/view?b={}".format(str(post.id())))

class viewpost(Handler):
    """ handler to display an individual blog entry """

    def render_viewpost(self,**kw):
        self.render("viewpost.html",**kw)

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
                blog=blog,e=e,viewpost=True)
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
                    e = self.delete_blog(user,blog)
                # form value is LIKE
                elif self.request.get('like'):
                    e = self.like_blog(user,blog,True)
                elif self.request.get('dislike'):
                    e = self.like_blog(user,blog,False)
            except ValueError:
                e = {'error':'Bad Blog Id'}
        except ValueError:
            e = {'error':'Please Login'}

        # if it was deleted render the blog form
        if not e:
            self.redirect("/blog")
        else:
            # otherwise re-render the view post
            blog = BlogPost.by_id(int(blog_id))
            self.render_viewpost(pagetitle="post: {}".format(blog.subject),blog=blog,e=e
                ,viewpost=True)
""" need to rework all this...

        # form value is POST COMMENT
        if self.request.get('postcomment'):
            # get the blog id and user id
            blog_id = self.request.get('blog_id')
            user_id = self.read_secure_cookie('user_id')

            # check a comment can be posted
            status, blog, e = BlogPost.can_comment(user,blog_id)
            if status:
                # can comment, so show comment
                self.render_viewpost(pagetitle="post: {}".format(blog.subject),blog=blog,e=e)
            else:
                # can't comment render error or bad blog id - render /blog
                if blog:
                    self.render_viewpost(pagetitle="post: {}".format(blog.subject),blog=blog,e=e)
                else:
                    self.redirect("/blog")

        # form value is CANCEL COMMENT
        if self.request.get('blogcancel'):
            blog_id = self.request.get('blog_id')

            # see if the blog id is valid
            try:
                blog = BlogPost.by_id(int(blog_id))
                e = {}
                # if it is valid, re-render the view post
                if blog:
                    self.render_viewpost(pagetitle="post: {}".format(blog.subject),blog=blog,e=e)
                else:
                    self.redirect("/blog")
            except ValueError:
                self.redirect("/blog")

        # form value is SAVE COMMENT
        if self.request.get('addcomment'):
            # get the blog id, user id, comment to be saved
            blog_id = self.request.get('blog_id')
            user_id = self.read_secure_cookie('user_id')
            comment = self.request.get('comment')

            # try to save the comment
            status, blog, e = BlogPost.add_comment(user_id,blog_id,comment)
            if status:
                # can comment, so show comment
                self.render_viewpost(pagetitle="post: {}".format(blog.subject),blog=blog,e=e)
            else:
                # can't comment render error or bad blog id - render /blog
                if blog:
                    self.render_viewpost(pagetitle="post: {}".format(blog.subject),blog=blog,e=e)
                else:
                    self.redirect("/blog")

        # form value is DELETE COMMENT
        if self.request.get('deletecomment'):
            # get the blog id, user id and comment id to be deleted
            blog_id = self.request.get('blog_id')
            user_id = self.read_secure_cookie('user_id')
            comment_id = self.request.get('comment_id')

            # see if the comment can be deleted
            status, blog, e = BlogPost.delete_comment(user_id,blog_id,comment_id)

            # if it can / was deleted, re-render the blog post
            if status:
                self.render_viewpost(pagetitle="post: {}".format(blog.subject),blog=blog,e=e)
            else:
                # if the delete failed, see if the blog id was ok
                if blog:
                    self.render_viewpost(pagetitle="post: {}".format(blog.subject),blog=blog,e=e)
                else:
                    # if the blog wasn't ok then show the blog page
                    self.redirect("/blog")

        # form value is EDIT COMMENT
        if (self.request.get('editcomment') == 'edit'):
            # get the blog, user and comment to be edited
            blog_id = self.request.get('blog_id')
            user_id = self.read_secure_cookie('user_id')
            comment_id = self.request.get('comment_id')

            # check whether the comment can be edited
            status, blog, e = BlogPost.can_edit_comment(user_id,blog_id,comment_id)

            # if the edit comment request was accepted, pass that fact to the template
            # this will show the comment in a text area input
            if status:
                self.render_viewpost(pagetitle="post: {}".format(blog.subject),blog=blog,e=e)
            else:
                try:
                    # see if the blog id was ok
                    blog = BlogPost.by_id(int(blog_id))
                    if blog:
                        self.render_viewpost(pagetitle="post: {}".format(blog.subject),blog=blog,e=e)
                except ValueError:
                    blog = None

                # otherwise re-render the blog page
                if not blog:
                    self.redirect("/blog")

        # form value is SAVE EDIT COMMENT
        if (self.request.get('editcomment') == 'editsave'):
            # get the form entries
            blog_id = self.request.get('blog_id')
            user_id = self.read_secure_cookie('user_id')
            comment_id = self.request.get('comment_id')
            comment = self.request.get('comment')

            # try to save the comment being edited
            status, blog, e = BlogPost.edit_comment(user_id,blog_id,comment_id,comment)

            # if everything was ok, re-render the view page
            if status:
                self.render_viewpost(pagetitle="post: {}".format(blog.subject),blog=blog,e=e)
            else:
                # otherwise, see if the blog id was ok and re-render the page with errors
                try:
                    blog = BlogPost.by_id(int(blog_id))
                    if blog:
                        self.render_viewpost(pagetitle="post: {}".format(blog.subject),blog=blog,e=e)
                except ValueError:
                    blog = None

                # otherwise, return to the blog page
                if not blog:
                    self.redirect("/blog")

        # form value is CANCEL EDIT COMMENT
        if (self.request.get('editcomment') == 'editcancel'):
            # get the blog id from the query parameters
            blog_id = self.request.get('blog_id')
            e = {}

            # test that the blog id is ok and get the blog entry
            try:
                blog = BlogPost.by_id(int(blog_id))

                # if the blog is found, render the view page
                if blog:
                    self.render_viewpost(pagetitle="post: {}".format(blog.subject),blog=blog,e=e)
            except ValueError:
                blog = None

            # the blog id was bad, go back to blogs
            if not blog:
                self.redirect("/blog")
...to here """

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
    debug=True)

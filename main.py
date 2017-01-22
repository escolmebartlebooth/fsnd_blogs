# imports start
import os
import jinja2
import webapp2
import re
import hmac
import logging
import hashlib
import random
import string

from google.appengine.ext import ndb

# end imports

# create jinja2 environment
TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), 'templates')
JINJA_ENV = jinja2.Environment(loader = jinja2.FileSystemLoader(TEMPLATE_DIR),
    autoescape=True)

# for hmac on cookies - should be somewhere else
SECRET_KEY = "Fdh3nhUsLhy"

# cookie cutters
def make_secure_val(val):
    return "{}|{}".format(val, hmac.new(SECRET_KEY,val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split("|")[0]
    if secure_val == make_secure_val(val):
        return val

# pwd functions
def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)

def valid_pw(name, pw, h):
    # TO DO: add try / except for bad passwords...
    salt = h.split(",")[1]
    if make_pw_hash(name, pw, salt) == h:
        return True
    else:
        return False

# data store entities

# user
class BlogUser(ndb.Model):
    username = ndb.StringProperty(required=True)
    pwd = ndb.StringProperty(required=True)
    email = ndb.StringProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add=True)

    @classmethod
    def by_id(cls,user_id):
        return cls.get_by_id(user_id)

    @classmethod
    def login(cls,username=None,password=None):
        # lookup username and if ok check pwd hash
        # return tuple of success, items and e
        status = False
        user = None
        e = {}
        if username:
            user = cls.query(cls.username == username).fetch(1)
            if user and valid_pw(username,password,user[0].pwd):
                user = user[0]
                status = True

        if not status:
            e = {'error':'invalid login'}

        return (status, user, e)

    @classmethod
    def signup(cls,username=None,password=None,verify=None,email=None):
        # create checkers
        user_re = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
        password_re = re.compile(r"^.{3,20}$")
        email_re = re.compile(r"^[\S]+@[\S]+.[\S]+$")
        # lookup username and if ok check pwd hash
        # return tuple of success, items and e
        status = True
        user = None
        e = {}
        if not (username and user_re.match(username)):
            status = False
            e['username'] = 'invalid username'

        if not (password and user_re.match(password)):
            status = False
            e['password'] = 'invalid password'
        elif (password != verify):
            status = False
            e['verify'] = 'passwords must match'

        if (email and not email_re.match(email)):
            status = False
            e['email'] = 'invalid email'

        if status:
            user = cls.query(cls.username == username).fetch(1)
            if user:
                status = False
                e['username'] = 'username exists'
            else:
                # signup user
                user = BlogUser(username=username,
                pwd=make_pw_hash(username,password),
                email=email).put()

        return (status, user, e)

# blog comment for structured property
class BlogComment(ndb.Model):
    userkey = ndb.KeyProperty(kind=BlogUser, required=True)
    username = ndb.StringProperty(required=True)
    comment = ndb.TextProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add=True)
    updated = ndb.DateTimeProperty(auto_now=True)

# blog
class Blog(ndb.Model):
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
        return cls.query().order(-cls.updated).fetch(n)

    @classmethod
    def add_comment(cls,user_id=None,blog_id=None,comment=None):
        status = True
        e = {}
        blog = None
        # is user?
        if not user_id:
            status = False
            e['error'] = 'you must login to do this'
            try:
                blog = Blog.by_id(int(blog_id))
            except ValueError:
                e['error'] = 'Bad blog id'
        else:
            try:
                # blog user ok?
                user = BlogUser.by_id(int(user_id))
                blog = Blog.by_id(int(blog_id))
                if (user.key == blog.userkey):
                    # is blog owned by user
                    status = False
                    e['error'] = 'you cannot do this as you do not own this post'
                else:
                    # post away...
                    # something wrong here
                    if comment:
                        # add comment
                        blog_comment = BlogComment(userkey=user.key,
                            username=user.username, comment=comment)
                        if blog.comments:
                            blog.comments.append(blog_comment)
                            blog.put()
                        else:
                            blog_comments = [blog_comment]
                            blog.comments = blog_comments
                            blog.put()
                    else:
                        status = False
                        e['error'] = 'Comment must not be empty'
            except ValueError:
                status = False
                e['error'] = 'Bad blog id'

        return (status, blog, e)

    @classmethod
    def can_comment(cls,user_id=None,blog_id=None):
        status = True
        e = {}
        blog = None
        # is user?
        if not user_id:
            status = False
            e['error'] = 'you must login to do this'
            try:
                blog = Blog.by_id(int(blog_id))
            except ValueError:
                e['error'] = 'Bad blog id'
        else:
            try:
                # blog user ok?
                user = BlogUser.by_id(int(user_id))
                blog = Blog.by_id(int(blog_id))
                if (user.key == blog.userkey):
                    # is blog owned by user
                    status = False
                    e['error'] = 'you cannot do this as you do not own this post'
                else:
                    # post away...
                    e['postcomment'] = 'can comment'
            except ValueError:
                status = False
                e['error'] = 'Bad blog id'

        return (status, blog, e)

    @classmethod
    def do_edit(cls,user_id=None,blog_id=None,subject=None,posting=None):
        # is user?
        status = True
        e = {}
        blog = None
        if not user_id:
            status = False
            e['error'] = 'you must login to do this'
        else:
            try:
                user = BlogUser.by_id(int(user_id))
                blog = Blog.by_id(int(blog_id))
                if (user.key != blog.userkey):
                    # is blog not owned by user
                    status = False
                    e['error'] = 'you cannot do this as you do not own this post'
                else:
                    # edit away...
                    if subject and posting:
                        blog.subject = subject
                        blog.blog = posting
                        blog.put()
                    else:
                        status = False
                        e['error'] = 'Bad subject or posting'
            except ValueError:
                status = False
                e['error'] = 'Bad blog id'

        return status, blog, e

    @classmethod
    def do_delete(cls,user_id=None,blog_id=None):
        # is user?
        status = True
        e = {}
        blog = None
        if not user_id:
            status = False
            e['error'] = 'you must login to do this'
        else:
            try:
                user = BlogUser.by_id(int(user_id))
                blog = Blog.by_id(int(blog_id))
                if (user.key != blog.userkey):
                    # is blog not owned by user
                    status = False
                    e['error'] = 'you cannot do this as you do not own this post'
                else:
                    # delete away...
                    blog.key.delete()
            except ValueError:
                status = False
                e['error'] = 'Bad blog id'

        return status, blog, e


    @classmethod
    def do_like(cls,user_id=None,blog_id=None,like_action=None):
        # is user?
        status = True
        e = {}
        blog = None
        if not user_id:
            status = False
            e['error'] = 'you must login to do this'
        else:
            try:
                user = BlogUser.by_id(int(user_id))
                blog = Blog.by_id(int(blog_id))
                logging.info(blog)
                if (user.key == blog.userkey):
                    # is blog owned by user
                    status = False
                    e['error'] = 'you cannot do this as you own this post'
                else:
                    # has blog been liked/disliked by user
                    if BlogLike.like_exists(blogkey=blog.key,userkey=user.key):
                        status = False
                        e['error'] = 'you cannot do this more than once'
                    else:
                        # if like, like and inc, else dislike
                        if like_action == 'like':
                            bloglike = BlogLike(userkey=user.key,
                                blogkey=blog.key,like=True).put()
                            if bloglike:
                                blog.likes += 1
                                blog.put()
                            else:
                                status = False
                                e['error'] = 'error posting like'
                        else:
                            bloglike = BlogLike(userkey=user.key,
                                blogkey=blog.key,like=False).put()
                            if bloglike:
                                blog.dislikes += 1
                                blog.put()
                            else:
                                status = False
                                e['error'] = 'error posting like'
            except ValueError:
                status = False
                e['error'] = 'Bad blog id'

        return status, blog, e


    @classmethod
    def by_id(cls,blog_id):
        return cls.get_by_id(blog_id)

    @classmethod
    def new_post(cls,user=None,subject="",posting=""):
        if not user or not subject or not posting:
            return None
        else:
            post=cls(username=user.username,userkey=user.key,subject=subject,
                blog=posting,likes=0,dislikes=0,comments=[])
            return post.put()

# blog comment for structured property
class BlogLike(ndb.Model):
    userkey = ndb.KeyProperty(kind=BlogUser, required=True)
    blogkey = ndb.KeyProperty(kind=Blog,required=True)
    like = ndb.BooleanProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add=True)

    @classmethod
    def like_exists(cls,blogkey=None,userkey=None):
        return cls.query(cls.blogkey==blogkey,cls.userkey==userkey).fetch(1)


# base handler
class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a,**kw)

    def render_str(self, template, **params):
        t = JINJA_ENV.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.id()))

    def logout(self):
        if self.user:
            self.response.headers.add_header('Set-Cookie',"user_id=; Path=/")
            self.redirect("/blog")
        else:
            self.redirect("/blog")

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header('Set-Cookie',"{}={}; Path=/".format(name,
            cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        user_id = self.read_secure_cookie('user_id')
        self.user = user_id and BlogUser.by_id(int(user_id))

class blog(Handler):
    def render_blog(self,**kw):
        self.render("blog.html",**kw)

    def get(self):
        # when written, get top 10 entries in desc order and pass...
        blogs = Blog.get_blogs(10)
        self.render_blog(pagetitle="welcome to bartlebooth blogs",blogs=blogs,e=None)

    def post(self):
        # work out which form was actioned
        user = self.read_secure_cookie("user_id")
        # form value is LIKE
        if self.request.get('like'):
            blog_id = self.request.get('blog_id')
            status, blog, e = Blog.do_like(user,blog_id,'like')
            blogs = Blog.get_blogs(10)
            self.render_blog(pagetitle="welcome to bartlebooth blogs",
                blogs=blogs,e=e)

        # form value is DISLIKE
        if self.request.get('dislike'):
            blog_id = self.request.get('blog_id')
            status, blog, e = Blog.do_like(user,blog_id,'dislike')
            blogs = Blog.get_blogs(10)
            self.render_blog(pagetitle="welcome to bartlebooth blogs",
                blogs=blogs,e=e)

        # form value is DELETE
        if self.request.get('blogdelete'):
            blog_id = self.request.get('blog_id')
            status, blog, e = Blog.do_delete(user,blog_id)
            blogs = Blog.get_blogs(10)
            self.render_blog(pagetitle="welcome to bartlebooth blogs",
                blogs=blogs,e=e)

class blogedit(Handler):
    def render_editpost(self,**kw):
        self.render("editpost.html",**kw)

    def get(self):
        # pass to handler function
        if self.request.get('b'):
            blog_id = self.request.get('b')
            status = True
            e = {}
            blog = None
            if not self.user:
                status = False
                e["error"] = "you must log in to do this"
            else:
                try:
                    # is logged in and owner
                    blog = Blog.by_id(int(blog_id))
                    if blog.userkey != self.user.key:
                        status = False
                        e["error"] = "you cannot edit as this is not your post"
                except:
                    status = False
                    e["error"] = "something went wrong"
            self.render_editpost(pagetitle="edit post",
                    blog=blog,e=e)

    def post(self):
        # send user, blog, subject, text to save_post...return errors if crook
        # not logged in, not owner, no subject, no post
        blog_id = self.request.get("blog_id")
        user_id = self.read_secure_cookie("user_id")
        subject = self.request.get("subject")
        posting = self.request.get("posting")

        status, blog, e = Blog.do_edit(user_id=user_id,blog_id=blog_id,
            subject=subject,posting=posting)
        if status:
            # show view post
            self.redirect("/blog/view?b={}".format(blog_id))
        else:
            # show error
            blog = Blog.by_id(int(blog_id))
            self.render_editpost(pagetitle="edit post",
                    blog=blog,e=e)


class logout(Handler):
    def get(self):
        # pass to handler function
        self.logout()

class signup(Handler):
    def render_signup(self,**kw):
        self.render("signup.html",**kw)

    def get(self):
        # pass to handler function
        self.render_signup(pagetitle="signup to bartlebooth blogs",items=None,e=None)

    def post(self):
        # pass to db handler to verify signup
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')
        # check if user valid
        status, user, e = BlogUser.signup(username,password,verify,email)
        # if not valid return error
        if status:
            self.login(user)
            self.redirect("/blog/welcome")
        else:
            items = {'username':username,'email':email}
            self.render_signup(pagetitle="signup to bartlebooth blogs",items=items,e=e)

class login(Handler):
    def render_login(self,**kw):
        self.render("login.html",**kw)

    def get(self):
        # pass to handler function
        self.render_login(pagetitle="login to bartlebooth blogs",items=None,e=None)

    def post(self):
        # capture values
        username = self.request.get('username')
        password = self.request.get('password')
        # check if user valid
        status, user, e = BlogUser.login(username,password)
        # if not valid return error
        if status:
            self.login(user.key)
            self.redirect("/blog/welcome")
        else:
            items = {'username':username}
            self.render_login(pagetitle="login to bartlebooth blogs",items=items,e=e)

class welcome(Handler):
    def render_welcome(self,**kw):
        self.render("welcome.html",**kw)

    def get(self):
        # check if valid user
        if self.user:
            # pass to handler function
            self.render_welcome(pagetitle="welcome to bartlebooth blogs {}".format(self.user.username))
        else:
            # pass to login page
            self.redirect("/blog/login")

class newpost(Handler):
    def render_newpost(self,**kw):
        self.render("newpost.html",**kw)

    def get(self):
        # check if valid user
        user = self.read_secure_cookie("user_id")
        if user:
            # pass to handler function
            self.render_newpost(pagetitle="new post",items=None,e=None)
        else:
            # pass to login page
            self.redirect("/blog/login")

    def post(self):
        # get input and logged on user
        subject = self.request.get('subject')
        posting = self.request.get('posting')
        user = self.read_secure_cookie("user_id")

        if not self.user:
            self.redirect("/blog/login")
        else:
            post = Blog.new_post(BlogUser.get_by_id(int(user))
                ,subject,posting)
            if not post:
                e = {'error':'Error on post'}
                items = {'subject':subject,'posting':posting}
                self.render_newpost(pagetitle="new post",items=items,e=e)
            else:
                self.redirect("/blog/view?b={}".format(str(post.id())))

class viewpost(Handler):
    def render_viewpost(self,**kw):
        self.render("viewpost.html",**kw)

    def get(self):
        # get query string
        blog_id = self.request.get('b')
        try:
            blog = Blog.by_id(int(blog_id))
            e = {}
            self.render_viewpost(pagetitle="post: {}".format(blog.subject),
                blog=blog,e=e)
        except ValueError:
            self.redirect("/blog")

    def post(self):
        # work out which form was actioned
        user = self.read_secure_cookie("user_id")

        # form value is LIKE
        if self.request.get('like'):
            blog_id = self.request.get('blog_id')
            status, blog, e = Blog.do_like(user,blog_id,'like')
            if status:
                self.render_viewpost(pagetitle="post: {}".format(blog.subject),
                    blog=blog,e=e)
            else:
                blog = Blog.by_id(int(blog_id))
                self.render_viewpost(pagetitle="post: {}".format(blog.subject),blog=blog,e=e)

        # form value is DISLIKE
        if self.request.get('dislike'):
            blog_id = self.request.get('blog_id')
            status, blog, e = Blog.do_like(user,blog_id,'dislike')
            if status:
                self.render_viewpost(pagetitle="post: {}".format(blog.subject),
                    blog=blog,e=e)
            else:
                blog = Blog.by_id(int(blog_id))
                self.render_viewpost(pagetitle="post: {}".format(blog.subject),blog=blog,e=e)

        # form value is DELETE
        if self.request.get('blogdelete'):
            blog_id = self.request.get('blog_id')
            status, blog, e = Blog.do_delete(user,blog_id)
            if status:
                self.redirect("/blog")
            else:
                blog = Blog.by_id(int(blog_id))
                self.render_viewpost(pagetitle="post: {}".format(blog.subject),blog=blog,e=e)

        # form value is POST COMMENT
        if self.request.get('postcomment'):
            blog_id = self.request.get('blog_id')
            user_id = self.read_secure_cookie('user_id')
            status, blog, e = Blog.can_comment(user,blog_id)
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
            try:
                blog = Blog.by_id(int(blog_id))
                e = {}
                if blog:
                    self.render_viewpost(pagetitle="post: {}".format(blog.subject),blog=blog,e=e)
                else:
                    self.redirect("/blog")
            except ValueError:
                self.redirect("/blog")

        # form value is SAVE COMMENT
        if self.request.get('addcomment'):
            blog_id = self.request.get('blog_id')
            user_id = self.read_secure_cookie('user_id')
            comment = self.request.get('comment')
            status, blog, e = Blog.add_comment(user,blog_id,comment)
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
        # form value is EDIT COMMENT
        # form value is SAVEEDITCOMMENT

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

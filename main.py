# imports start
import os
import jinja2
import webapp2

from google.appengine.ext import ndb

# end imports

# imports end

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
        if username:
            user = cls.query(cls.username == username).fetch(1)
            if user and valid_pw(username,password,user[0].pwd):
                status = True

        if not status:
            e = {'error':'invalid login'}

        return (status, user, e)

# blog comment for structured property
class BlogComment(ndb.Model):
    userkey = ndb.KeyProperty(kind=BlogUser, required=True)
    username = ndb.StringProperty(required=True)
    comment = ndb.TextProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add=True)
    updated = ndb.DateTimeProperty(auto_now=True)

# blog
class blog(ndb.Model):
    username = ndb.StringProperty(required=True)
    userkey = ndb.KeyProperty(kind=BlogUser,required=True)
    subject = ndb.StringProperty(required=True)
    blog    = ndb.TextProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add=True)
    updated = ndb.DateTimeProperty(auto_now=True)
    likes = ndb.IntegerProperty()
    dislikes = ndb.IntegerProperty()
    comments = ndb.StructuredProperty(BlogComment,repeated=True)

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
        self.render_blog(pagetitle="welcome to bartlebooth blogs")

class logout(Handler):
    def get(self):
        # pass to handler function
        self.logout()

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
            self.login(user)
            self.redirect("blog/welcome")
        else:
            items = {'username':username}
            self.render_login(pagetitle="login to bartlebooth blogs",items=items,e=e)

# register page handlers
app = webapp2.WSGIApplication([
    ('/blog', blog),
    ('/blog/logout', logout),
    ('/blog/login', login),
    #('/blog/signup', signup),
    #('/blog/welcome', welcome),
    #('/blog/blogpost', blogpost),
    #('/blog/blogedit', blogedit),
    #('/blog/(\d+)', blogview)
    ],
    debug=True)

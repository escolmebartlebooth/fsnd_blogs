# imports start
import os
import jinja2
import webapp2
import re
import bb_blogdb as bdb

import logging


# end imports

# create jinja2 environment
TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), 'templates')
JINJA_ENV = jinja2.Environment(loader=jinja2.FileSystemLoader(TEMPLATE_DIR),
                               autoescape=True)


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
            user = bdb.BlogUser.login(username, password)

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
            user = bdb.BlogUser.signup(username, password, email)
            if user:
                # if registered successfully, log the user in
                self.set_secure_cookie('user_id', str(user.id()))
            else:
                e['username'] = 'username exists'

        return (user, e)

    def blog_exists(self, blog_id=None):
        """ helper to determine if a blog id is valid """
        try:
            blog = bdb.BlogPost.by_id(int(blog_id))
            return blog
        except (TypeError, ValueError):
            return None

    def user_owns_blog(self, user=None, blog=None):
        """ helper to determine if a blog id is valid """
        if (user.key == blog.userkey):
            return True
        else:
            return False

    def logout(self):
        """ clear the user_id cookie if the User is set """

        if self.user:
            self.response.headers.add_header('Set-Cookie', "user_id=; Path=/")
        self.redirect("/blog")

    def delete_blog(self, user=None, blog=None):
        """ check that the user owns the blog and if so delete it """
        if not user:
            return {'error': 'you must be logged in'}
        elif not bdb.BlogPost.user_owns_blog(user, blog):
            return {'error': 'you do not own this blog'}
        elif not bdb.BlogPost.delete_blog(blog):
            return {'error': 'deletion failed'}
        else:
            return None

    def set_secure_cookie(self, name, val):
        """
            create a secure cookie from the passed value
            and store against the name
        """

        cookie_val = bdb.make_secure_val(val)
        self.response.headers.add_header('Set-Cookie',
                                         "{}={}; Path=/".format(name,
                                                                cookie_val))

    def read_secure_cookie(self, name):
        """ read the cookie from the browser """
        cookie_val = self.request.cookies.get(name)
        return cookie_val and bdb.check_secure_val(cookie_val)

    def initialize(self, *a, **kw):
        """ used to access the user cookie and store against the handler """

        webapp2.RequestHandler.initialize(self, *a, **kw)
        user_id = self.read_secure_cookie('user_id')
        self.user = user_id and bdb.BlogUser.by_id(int(user_id))


class blog(Handler):
    """ handler for the main app page to display and edit blogs """

    def render_blog(self, **kw):
        self.render("blog.html", **kw)

    def get(self):
        """ get the ten most recent blog entries and render the page """
        blogs = bdb.BlogPost.get_blogs(10)
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
            user = bdb.BlogUser.by_id(int(user_id))
            try:
                # the blog and user from the ids
                blog = bdb.BlogPost.by_id(int(blog_id))

                # form value is DELETE and the blog exists
                if blog and self.request.get('blogdelete'):
                    # pass deletion to a common handler
                    e = self.delete_blog(user, blog)
            except ValueError:
                e = {'error': 'Bad Blog Id'}
        except (TypeError, ValueError):
                e = {'error': 'Please Login'}

        blogs = bdb.BlogPost.get_blogs(10)
        self.render_blog(pagetitle="welcome to bartlebooth blogs",
                         blogs=blogs, e=e)


class blogedit(Handler):
    """ Handle updates to blog posts """

    def render_editpost(self, **kw):
        self.render("editpost.html", **kw)

    def get(self, blog_id):
        """
            get the blog from the query parameter
            check user owns the blog
        """

        e = {}
        blog = None
        user_id = self.read_secure_cookie("user_id")

        try:
            # is the user valid
            user = bdb.BlogUser.by_id(int(user_id))
            try:
                # test the blog is valid
                blog = bdb.BlogPost.by_id(int(blog_id))
                # blog isn't valid
                if not blog:
                    self.redirect('/blog')
                else:
                    # does the user own the blog
                    if not bdb.BlogPost.user_owns_blog(user, blog):
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
            user = bdb.BlogUser.by_id(int(user_id))
            try:
                # test blog
                blog = bdb.BlogPost.by_id(int(blog_id))
                # test blog exists
                if blog:
                    # see if the user owns the blog
                    if not bdb.BlogPost.user_owns_blog(user, blog):
                        e['error'] = 'You do not own this blog'
                    elif not (subject and posting):
                        # set a post error instead of an error to show save button
                        e['posterror'] = 'subject and posting must not be empty'
                    else:
                        # blog is owned by the user so can edit and entry is fine
                        bdb.BlogPost.edit_blog(blog=blog, subject=subject,
                                               posting=posting)
                else:
                    e['error'] = 'bad blog id'
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
            post = bdb.BlogPost.new_post(bdb.BlogUser.get_by_id(int(user)),
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

    def get(self, blog_id):
        """
            get the blog_id on the query string and test it's validity
            if ok, show the blog, if not sliently redirect to the /blog page
        """
        e = {}
        try:
            # fetch the blog entity then render the view page
            blog = bdb.BlogPost.by_id(int(blog_id))
            if blog:
                self.render_viewpost(pagetitle="post: {}".format(blog.subject),
                                     blog=blog, e=e, viewpost=True)
            else:
                # bad blog id
                self.redirect("/blog")
        except (TypeError, ValueError):
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
            user = bdb.BlogUser.by_id(int(user_id))
            try:
                # get the blog entry and user
                blog = bdb.BlogPost.by_id(int(blog_id))

                # blog exists and form value is DELETE
                if blog and self.request.get('blogdelete'):
                    # pass deletion to a common handler
                    e = self.delete_blog(user, blog)
                """ # form value is POST COMMENT
                elif self.request.get('postcomment'):
                    if bdb.BlogPost.user_owns_blog(user, blog):
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
                        if bdb.BlogPost.user_owns_blog(user, blog):
                            e['error'] = 'You cannot comment on this blog'
                        else:
                            # save the comment
                            e = bdb.BlogPost.add_comment(user, blog, comment)
                    else:
                        e['error'] = 'comment cannot be blank'
                # form value is DELETE COMMENT
                elif self.request.get('deletecomment'):
                    comment_id = self.request.get('comment_id')
                    if bdb.BlogPost.user_owns_comment(user, blog, comment_id):
                        e = bdb.BlogPost.delete_comment(blog, comment_id)
                    else:
                        e['error'] = 'You do not own this comment'
                # form value is EDIT COMMENT - EDIT
                elif self.request.get('editcomment'):
                    comment_id = self.request.get('comment_id')
                    if bdb.BlogPost.user_owns_comment(user, blog, comment_id):
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
                        if not bdb.BlogPost.user_owns_comment(user, blog,
                                                              comment_id):
                            e['error'] = 'You cannot edit this comment'
                        else:
                            # save the comment
                            e = bdb.BlogPost.save_comment(user, blog,
                                                          comment_id, comment)
                    else:
                        e['error'] = 'comment cannot be blank' """
            except ValueError:
                e = {'error': 'Bad Blog Id'}
        except (TypeError, ValueError):
            e = {'error': 'Please Login'}
        # if it was deleted render the blog form
        if not e:
            self.redirect("/blog")
        else:
            # otherwise re-render the view post
            blog = bdb.BlogPost.by_id(int(blog_id))
            self.render_viewpost(pagetitle="post: {}".format(blog.subject),
                                 blog=blog, e=e, viewpost=True)

class bloglike(Handler):
    """ handler to manage the actions of liking a blog """

    def post(self):
        """
            check if the user is logged in
            check if the user owns the blog
            check if this user has liked/disliked this blog
            update the like / dislike
        """
        referer = self.request.referer
        blog_id = self.request.get('blog_id')
        if self.request.get('like'):
            like_action = True
        elif self.request.get('dislike'):
            like_action = False

        if self.user:
            # see if the user is logged in
            try:
                blog = bdb.BlogPost.by_id(int(blog_id))
                # test blog returned isn't None
                if (blog and not bdb.BlogPost.user_owns_blog(self.user, blog)
                    and not bdb.BlogLike.like_exists(self.user, blog)):
                    # post the like with the like action
                    bdb.BlogPost.like_blog(self.user, blog, like_action)
            except (TypeError, ValueError):
                self.redirect('/blog')
            self.redirect(referer)
        else:
            # bad user id, show login
            self.redirect('/blog/login')

class blogcomment(Handler):
    """ handler to manage commenting on a blog """

    def get(self, blog_id):
        """ test whether logged in and not owner """
        blog = self.blog_exists(blog_id)
        if self.user and not self.user_owns_blog(self.user, blog) and blog:
            e = {'postcomment': True}
            self.render("viewpost.html",
                        pagetitle="post: {}".format(blog.subject),
                        blog=blog, e=e, viewpost=True)
        else:
            self.redirect(self.request.referer)


# register page handlers
app = webapp2.WSGIApplication([
    ('/blog', blog),
    ('/blog/logout', logout),
    ('/blog/login', login),
    ('/blog/signup', signup),
    ('/blog/welcome', welcome),
    ('/blog/new', newpost),
    ('/blog/([0-9]+)', viewpost),
    ('/blog/edit/([0-9]+)', blogedit),
    ('/blog/comment/([0-9]+)', blogcomment),
    ('/blog/like', bloglike)
    ],
    debug=False)

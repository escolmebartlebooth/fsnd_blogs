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
        """
            helper to determine if a blog id is valid
            return the blog entity if it exists
            otherwise return None
        """

        try:
            blog = bdb.BlogPost.by_id(int(blog_id))
            return blog
        except (TypeError, ValueError):
            return None

    def user_owns_blog(self, user=None, blog=None):
        """ helper to determine if a user owns the blog """

        if (user.key == blog.userkey):
            return True
        else:
            return False

    def user_owns_comment(self, user=None, blog=None, comment_id=None):
        """
            helper function to check that the user owns the comment
            try to cast the id as an integer
            then check if the comment is owned by the user
            return true if the user does own the user
        """
        try:
            # is the comment id an integer
            comment_id = int(comment_id)
            if (user.key == blog.comments[comment_id].userkey):
                # the user does own the comment
                return True
            else:
                return False
        except:
            # bad comment id
            return False

    def delete_blog(self, user=None, blog=None):
        """ check that the user owns the blog and if so delete it """

        if self.user_owns_blog(user, blog):
            return bdb.BlogPost.delete_blog(blog)
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
        """ process the delete form that is on the blog main page """

        # get the blog id from the form entries
        blog_id = self.request.get('blog_id')

        if self.user:
            # the user is logged in, does the blog exist?
            blog = self.blog_exists(blog_id)

            # form value is DELETE and the blog exists
            if blog and self.request.get('blogdelete'):
                # pass deletion to a common handler
                self.delete_blog(self.user, blog)

            # re-render the blogs page
            self.redirect('/blog')
        else:
            # user isn't logged in so show the login page
            self.redirect('/blog/login')


class blogedit(Handler):
    """ Handle updates to blog posts """

    def render_editpost(self, **kw):
        self.render("editpost.html", **kw)

    def get(self, blog_id):
        """
            get the blog from the query parameter
            check user owns the blog
        """
        if self.user:
            # user valid
            blog = self.blog_exists(blog_id)
            if blog and self.user_owns_blog(self.user, blog):
                # blog is valid and owned by the user so render the edit form
                self.render_editpost(pagetitle="edit post", blog=blog, e=None)
            else:
                # TO DO SHOW ERROR ON REFERRER FORM?
                self.redirect(self.request.referer)
        else:
            # not logged in so show the login page
            self.redirect('/blog/login')

    def post(self, post_id):
        """
            Check the user, blog and subject/comment entries
            then post or fail the edit
        """

        # get the form values from the edit post
        blog_id = self.request.get("blog_id")
        subject = self.request.get("subject")
        posting = self.request.get("posting")

        if self.user:
            # user valid
            blog = self.blog_exists(blog_id)
            # test blog exists and the user owns the form
            if blog and self.user_owns_blog(self.user, blog):
                if (subject and posting):
                    # save the edit and redirect to blog post
                    bdb.BlogPost.edit_blog(blog=blog, subject=subject,
                                           posting=posting)
                    self.redirect('/blog/{}'.format(str(blog_id)))
                else:
                    # subject and posting shouldn't be empty so error
                    e = {'posterror': 'subject and posting must not be empty'}
                    self.render_editpost(pagetitle="edit post",
                                         blog=blog, e=e)
            else:
                # TO DO - SHOULD THIS BE AN ERROR?
                self.redirect('/blog')
        else:
            self.redirect('/blog/login')


class logout(Handler):
    """
        Handle a GET to the /blog/logout page
    """

    def get(self):
        """ clear the user_id cookie if the User is set """

        if self.user:
            self.response.headers.add_header('Set-Cookie', "user_id=; Path=/")
        self.redirect("/blog")


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

        if self.user:
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

        if not self.user:
            # if the user isn't valid, go to the login page
            self.redirect("/blog/login")
        elif not subject or not posting:
            # if either subject or post is empty, raise an error
            e = {'error': "Subject and Post cannot be blank"}
            items = {'subject': subject, 'posting': posting}
            self.render_newpost(pagetitle="new post", items=items, e=e)
        else:
            post = bdb.BlogPost.new_post(self.user,
                                         subject, posting)
            self.redirect("/blog/{}".format(str(post.id())))


class viewpost(Handler):
    """ handler to display an individual blog entry """

    def render_viewpost(self, **kw):
        self.render("viewpost.html", **kw)

    def get(self, blog_id):
        """
            get the blog_id on the query string and test it's validity
            if ok, show the blog, if not sliently redirect to the /blog page
        """
        blog = self.blog_exists(blog_id)
        if blog:
            # blog exists so show the view page
            self.render_viewpost(pagetitle="post: {}".format(blog.subject),
                                 blog=blog, e=None, viewpost=True)
        else:
            self.redirect("/blog")

    def post(self, post_id):
        """ handler for the multiple forms on the view page """

        # get the blog id
        blog_id = self.request.get('blog_id')

        if self.user:
            # user is valid
            blog = self.blog_exists(blog_id)
            # test if the blog exists and a deletion request
            if blog and self.request.get('blogdelete'):
                # pass deletion to a common handler
                self.delete_blog(self.user, blog)
            # TO DO should there be a better error handler here?
            self.redirect("/blog")
        else:
            # not logged in so show login page
            self.redirect('/blog/login')


class bloglike(Handler):
    """ handler to manage the actions of liking a blog """

    def post(self):
        """
            check if the user is logged in
            check if the user owns the blog
            check if this user has liked/disliked this blog
            update the like / dislike
        """
        blog_id = self.request.get('blog_id')

        # check whether its a like or dislike request
        if self.request.get('like'):
            like_action = True
        elif self.request.get('dislike'):
            like_action = False

        if self.user:
            # see if the user is logged in
            blog = self.blog_exists(blog_id)
            # see if the blog exists and the user owns the blog
            if (blog and not self.user_owns_blog(self.user, blog) and not
                bdb.BlogLike.like_exists(self.user, blog)):
                # post the like with the like action
                bdb.BlogPost.like_blog(self.user, blog, like_action)
            # TO DO better handler here?
            self.redirect(self.request.referer)
        else:
            # bad user id, show login
            self.redirect('/blog/login')


class blogcomment(Handler):
    """ handler to manage commenting on a blog """

    def get(self, blog_id):
        """ test whether logged in and not owner """
        blog = self.blog_exists(blog_id)
        if self.user:
            if not self.user_owns_blog(self.user, blog) and blog:
                # postcomment True means a textarea will show on the viewpost
                e = {'postcomment': True}
                self.render("viewpost.html",
                            pagetitle="post: {}".format(blog.subject),
                            blog=blog, e=e, viewpost=True)
            else:
                # TO DO check whether better referrer
                self.redirect(self.request.referer)
        else:
            # bad user id
            self.redirect('/blog/login')

    def post(self, blog_id):
        """ save the comment if logged in and the comment is ok """
        blog = self.blog_exists(blog_id)
        if self.user:
            # user is logged in
            if not self.user_owns_blog(self.user, blog) and blog:
                comment = self.request.get('comment')
                if comment:
                    # comment isn't empty
                    bdb.BlogPost.add_comment(self.user, blog, comment)
                    e = None
                else:
                    e = {'error': 'comment cannot be blank'}
            else:
                e = {'error': 'error'}
            # TO DO better error handler re blog v owns blog
            self.render("viewpost.html",
                        pagetitle="post: {}".format(blog.subject),
                        blog=blog, e=e, viewpost=True)
        else:
            # user not logged in
            self.redirect('/blog/login')


class blogdeletecomment(Handler):
    """ handler to manage deleting a comment on a blog """

    def post(self):
        """ test whether logged in and not owner """
        # get form values if a delete comment request
        if (self.request.get('deletecomment')):
            blog_id = self.request.get('blog_id')
            comment_id = self.request.get('comment_id')
            blog = self.blog_exists(blog_id)
            if self.user:
                if (self.user_owns_comment(self.user, blog,
                                           comment_id) and blog):
                    # delete comment
                    bdb.BlogPost.delete_comment(blog, comment_id)
                # TO DO error handler?
                self.redirect('/blog/{}'.format(int(blog_id)))
            else:
                # user not logged in
                self.redirect('/blog/login')
        else:
            # TO DO review this
            self.redirect(self.request.referer)


class blogeditcomment(Handler):
    """ handler to manage edit comments on a blog """

    def get(self, blog_id):
        """ test whether logged in and not owner """
        blog = self.blog_exists(blog_id)
        comment_id = self.request.get('cid')
        try:
            comment_index = int(comment_id)
            if self.user:
                # user logged in
                if (self.user_owns_comment(self.user,
                                           blog, comment_index) and blog):
                    e = {'editcomment': comment_id}
                else:
                    e = {}
                # TO DO review error handler
                self.render("viewpost.html",
                            pagetitle="post: {}".format(blog.subject),
                            blog=blog, e=e, viewpost=True)
            else:
                # bad login
                self.redirect('/blog/login')
        except:
            # TO DO review this
            self.redirect(self.request.referer)

    def post(self, blog_id):
        """ save the comment if logged in and the comment is ok """
        blog = self.blog_exists(blog_id)
        comment = self.request.get('updatecomment')
        comment_id = self.request.get('comment_id')
        if self.user:
            # user logged in
            if (self.user_owns_comment(self.user, blog, comment_id) and blog):
                try:
                    comment_index = int(comment_id)
                    if comment:
                        # comment isn't empty
                        bdb.BlogPost.save_comment(self.user, blog,
                                                  comment_index, comment)
                        e = None
                    else:
                        e = {'error': 'comment cannot be blank'}
                        e['editcomment'] = comment_id
                    # TO DO review errors
                    self.render("viewpost.html",
                                pagetitle="post: {}".format(blog.subject),
                                blog=blog, e=e, viewpost=True)
                except ValueError:
                    # TO DO review this
                    self.redirect(self.request.referer)
            else:
                # TO DO review this
                self.redirect(self.request.referer)
        else:
            # user not logged in
            self.redirect('/blog/login')


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
    ('/blog/editcomment/([0-9]+)', blogeditcomment),
    ('/blog/deletecomment', blogdeletecomment),
    ('/blog/like', bloglike)
    ],
    debug=False)

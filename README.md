# Udacity Full Stack Nano-degree: Multi-User Blog

## location

The blog is available at: https://bartlebooth-blog.appspot.com/blog

## Implementation

### Pre-Requisites

This project was built using Google App Engine (SDK Verison 138.0.0 / python engine: v.1.9.49)

In addition to the bespoke code, the following imports are made:

+ os
+ jinja2
+ webapp2
+ re
+ hmac
+ hashlib
+ random
+ string

+ from google.appengine.ext import ndb

### Files

+ main.py: main python code file containing google datastore entity definitions and page handlers for the site
+ app.yaml: definition file for the app engine
+ /css/blog.css: CSS file for styling
+ /img/*.{jpg,svg}: images for a thumbs up / down for like / dislike
+ /templates/*.html: repository for HTML templates

### Implementation notes

+ imported font from googlefont api (Baumans)
+ media query breakpoints in blog.css for mobile viewports at 420px

#### template structure

all pages use base.html to create the header and a page title in the body. most pages also use navigation.html to add a menu bar.

login and signup pages are used to handle user access with welcome as the target of both for successful login. logout is only present as a handler not a page template.

blog, viewpost, editpost, newpost handle displaying the the blog entries for list, view, edit, and new. the templates blogpost and blogcomment are used within these templates to display one or more blog entries or comments.

#### code structure

several handlers manage flow control:

+ login, signup, welcome, logout all manage the user access flows and typically read from or set a user cookie on successful login, which all pages can then handle.
+ blog handles the display of a list of blog posts and posts to create a new post, like or dislike a post, view a post, edit a post or delete a post
+ viewpost handles the display of a single post and can also handle edit and delete post as well as add, edit or delete a comment - blogview itself changes state to handle comment addition and editing
+ editpost and newpost handlers handle the creation of a newpost and the editing of an existing post

#### data structures

+ Blog contains each blog post entry, including which user posted the blog, its subject, content, number of likes / dislikes and data information for creation and updating. In addition it holds a structured property BlogComment and also a number of class methods to handle post creation, editing, deletion as well as liking/disliking a post
+ BlogLike records which user has liked/disliked a blog and allows control of the number of times a blog is liked/disliked by a particular user
+ BlogUser holds the user credentials of signed up users with users passwords being hashed

#### key business rules

+ User MUST be logged in to create, edit or delete posts as well as like / dislike a post and to comment on posts
+ Only a blog owner can edit or delete a post
+ A blog owner cannot like / dislike a post or post a comment against a post
+ A user can only like/dislike a post once and only the owner of a comment can edit or delete it
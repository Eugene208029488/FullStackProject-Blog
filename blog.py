import os
import re
import random
import hashlib
import hmac
import logging
from string import letters
import webapp2
import jinja2
import time
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

secret = 'blogger'


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)

# user stuff


def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


def users_key(group='default'):
    return db.Key.from_path('users', group)


class BlogHandler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


class MainPage(BlogHandler):

    def get(self):
        self.write('Hello, Udacity!')


class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return cls.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = cls.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return cls(parent=users_key(),
                   name=name,
                   pw_hash=pw_hash,
                   email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


# blog stuff

def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    createdby = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    likes = db.IntegerProperty(default=0)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)


class Comment(db.Model):
    post = db.ReferenceProperty(Post,
                                collection_name='user_comments')
    content = db.TextProperty()
    createdby = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)


class Userlikes(db.Model):
    post = db.ReferenceProperty(Post,
                                collection_name='user_likes')
    username = db.StringProperty()


class BlogFront(BlogHandler):

    def get(self):
        posts = Post.all().order('-created')
        #posts = db.GqlQuery("select * from Post order by created desc limit 10")
        self.render('front.html', posts=posts)


class PostPage(BlogHandler):

    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return
        comments = post.user_comments.order('-last_modified')
        self.render("permalink.html", post=post, comments=comments)

    def post(self, post_id):

        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        comment = self.request.get('comment')
        error_comment = ""
        if comment and self.user:
            Comment(post=post,
                    content=comment,
                    createdby=self.user.name).put()
        elif not self.user:
            error_comment = "Login or signup to post comment."
        else:
            error_comment = "Please enter a comment."

        time.sleep(0.1)  #added a delay to make sure it refresh with the latest data in the datastore
        comments = post.user_comments.order('-last_modified')
        self.render(
            "permalink.html", post=post, error_comment=error_comment, comments=comments)


class NewPost(BlogHandler):

    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/login')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content and self.user:
            p = Post(parent=blog_key(), subject=subject,
                     content=content, createdby=self.user.name)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render(
                "newpost.html", subject=subject, content=content, error=error)


class EditPost(BlogHandler):

    def get(self, post_id):
        if not self.user:
            self.redirect("/login")

        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        if self.user and post.createdby == self.user.name:
            self.render(
                "editpost.html", subject=post.subject,
                content=post.content, post_id=post_id)
        else:
            error = "You can only edit post you created."
            self.render("permalink.html", post=post, error=error)

    def post(self, post_id):
        if not self.user:
            self.redirect('/login')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content and self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            p = db.get(key)
            p.subject = subject
            p.content = content
            p.put()
            time.sleep(0.1)  #added a delay to make sure it refresh with the latest data in the datastore
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render(
                "editpost.html", subject=subject, content=content, error=error)


class DeletePost(BlogHandler):

    def get(self, post_id):
        if not self.user:
            self.redirect("/login")

        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        if post and self.user and post.createdby == self.user.name:
            post.delete()
            time.sleep(0.1)  #added a delay to make sure it refresh with the latest data in the datastore
            self.redirect('/blog')
        else:
            error = "You can only delete post you created."
            self.render("permalink.html", post=post, error=error)


class EditComment(BlogHandler):

    def get(self, comment_id):
        if not self.user:
            self.redirect("/login")

        key = db.Key.from_path('Comment', int(comment_id))
        comment = db.get(key)
        key2 = db.Key.from_path(
            'Post', int(comment.post.key().id()), parent=blog_key())
        post = db.get(key2)

        if self.user and comment.createdby == self.user.name:
            self.render(
                "editcomment.html", content=comment.content,
                post_id=post.key().id())
        else:
            error = "You can only edit comment you created."
            self.render("permalink.html", post=post, error=error)

    def post(self, comment_id):
        if not self.user:
            self.redirect('/login')

        content = self.request.get('content')

        if content and self.user:
            key = db.Key.from_path('Comment', int(comment_id))
            c = db.get(key)
            c.content = content
            c.put()
            time.sleep(0.1)
            self.redirect('/blog/%s' % str(c.post.key().id()))
        else:
            error = "Please enter a comment."
            self.render("editcomment.html", content=content, error=error)


class DeleteComment(BlogHandler):
    #Handler to delete comment

    def get(self, comment_id):
        if not self.user:
            self.redirect("/login")

        key = db.Key.from_path('Comment', int(comment_id))
        comment = db.get(key)

        key2 = db.Key.from_path(
            'Post', int(comment.post.key().id()), parent=blog_key())
        post = db.get(key2)

        if not comment:
            self.error(404)
            return

        if comment and self.user and comment.createdby == self.user.name:
            comment.delete()
            time.sleep(0.1)
            self.redirect('/blog/%s' % str(post.key().id()))
        else:
            error = "You can only delete post you created."
            self.render("permalink.html", post=post, error=error)


class LikePost(BlogHandler):
    #handler to allow user to like or unlike post.  It will also ensure that a user can only like once and cannot like their own post.
    #It will also count the # of likes per user

    def get(self, post_id):
        if not self.user:
            self.redirect("/login")

        posts = Post.all().order('-created')

        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if self.user:
            likes = post.user_likes.filter('username =', self.user.name)
            likes_ctr = post.likes

            if post.createdby == self.user.name:
                error = "You cannot like your own post."
                self.render('front.html', posts=posts, error=error)
            else:
                if not likes.get():
                    likes_ctr += 1
                    Userlikes(post=post,
                              username=self.user.name).put()
                else:
                    likes_ctr -= 1
                    likes.get().delete()
                post.likes = likes_ctr
                post.put()
                time.sleep(0.1)
                self.redirect(self.request.referer)


class Signup(BlogHandler):

    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class Register(Signup):

    def done(self):
        # make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/welcome')


class Login(BlogHandler):

    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/welcome')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error=msg)


class Logout(BlogHandler):

    def get(self):
        self.logout()
        self.redirect('/login')


class Welcome(BlogHandler):

    def get(self):
        if self.user:
            self.render('welcome.html', username=self.user.name)
        else:
            self.redirect('/signup')


app = webapp2.WSGIApplication([('/', BlogFront),
                               ('/blog', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/blog/editpost/([0-9]+)', EditPost),
                               ('/blog/deletepost/([0-9]+)', DeletePost),
                               ('/blog/editcomment/([0-9]+)', EditComment),
                               ('/blog/deletecomment/([0-9]+)', DeleteComment),
                               ('/blog/likepost/([0-9]+)', LikePost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/welcome', Welcome),
                               ],
                              debug=True)

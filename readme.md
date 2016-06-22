#Multi User Blog

Multi user blog is where users can sign in and post blog posts as well as 'Like' and 'Comment' on other posts made on the blog. This blog will be hosted on Google App Engine and will also have an authentication system for users to be able to register and sign in and then create blog posts!

#Technology used:
1. Google App Engine for Python- for hosting
2. Jinja2 - template
3. Google Cloud Datastore - NoSQL Schemaless Database
4. hmac/hashlib - for hashing password
5. Python Regular Expression - to validate username and password text pattern

#Instructions
1. Access the blog using this [link](http://blog-eugene-134416.appspot.com/blog) http://blog-eugene-134416.appspot.com/blog
2. You will need to signup or login before you can create a new blog, post comments or like any blog.
  * Username will be unique.
3. You can post a new blog once you login.  You can create a new blog by clicking the 'Post a blog' link located beside the login/signup link.
4. Clicking the Blog title will redirect you to the blog page and provide edit/delete option as well as post comments.
  * You can only edit or delete blog you create.
  * You can only edit or delete comment you create.
5. You can 'like' a post by clicking the 'like' icon.
  * You cannot like your own post.
  * You can only like once per post.
  * Reclicking the 'like' icon will unlike the post.
  * There will be a counter of the # of likes per post.



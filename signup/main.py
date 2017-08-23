import os
import jinja2
import webapp2
import re
import random
import string
import hashlib
from google.appengine.ext import db






def make_pw_hash(pw):

    h = hashlib.sha256(pw).hexdigest()
    return h

def valid_pw(pw, h):

    return h == make_pw_hash(pw)




def valid_username(username):
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    return USER_RE.match(username)

def valid_password(pwd):
    PWD_RE = re.compile(r"^.{3,20}$")
    return PWD_RE.match(pwd)

def valid_email(email):
    EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
    return EMAIL_RE.match(email)

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape=True)

class userDB(db.Model):


    username = db.StringProperty()
    password = db.StringProperty()
    email = db.StringProperty()


def signup_key(name = 'default'):
    return db.Key.from_path('signup', name)


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)
    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)
    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))


class SignUp(Handler):

    def get(self):

        self.render("signup.html")

    def post(self):



        count = 0

        username = self.request.get("username")
        pwd = self.request.get("password")
        verify = self.request.get("verify")
        email = self.request.get("email")
        usererror=""
        pwderror=""
        cmperror=""
        emailerror=""

        db1=userDB(parent = signup_key(), username=username, password=pwd, email=email)
        check = db.GqlQuery(" select * from userDB where username = :name ", name = username).get()

        if  check != None:
            usererror="User exists in the system"
            count += 1

        else:
            if valid_username(username) != None:

                if valid_password(pwd) != None:
                    if verify != pwd:
                        cmperror = "Your passwords didn't match."
                        count += 1
                elif valid_password(pwd) == None:
                        pwderror = "That wasn't a valid password."
                        count += 1




            elif valid_username(username) == None:
                usererror = "That's not a valid username."
                count += 1
                if valid_password(pwd) != None:
                    if verify != pwd:
                        cmperror = "Your passwords didn't match."
                        count += 1
                elif valid_password(pwd) == None:
                        pwderror = "That wasn't a valid password."
                        count += 1

            if (email):
                if valid_email(email) == None:
                    emailerror = "That's not a valid email."
                    count += 1












        if count > 0:
            self.render("signup.html", username=username, email=email, usererror=usererror, pwderror=pwderror,
                        cmperror=cmperror, emailerror=emailerror)

        elif count == 0:



            db1.put()
            user_id = str(db1.key().id())

            self.response.headers.add_header('Set-Cookie', 'user_id=%s|%s; Path=/'%(str(user_id), make_pw_hash(user_id)))




            self.redirect('/welcome')

class Welcome(Handler):

    def get(self):

        rcookie = self.request.cookies.get('user_id')

        if rcookie == "":
            self.redirect("/signup")
        else:


            user_id= rcookie.split("|")[0]
            h = rcookie.split("|")[1]



            if h == make_pw_hash(user_id):

                key = db.Key.from_path('userDB', int(user_id), parent=signup_key())

                user = db.get(key)

                self.render("welcome.html", username = user.username)

            else:
                self.redirect("/signup")


class Login(Handler):

    def get(self):
        self.render("login.html")

    def post(self):

        username = self.request.get("username")
        pwd = self.request.get("password")
        check = db.GqlQuery(" select * from userDB where username = :name and password =:pwd"
            , name = username, pwd=pwd).get(keys_only=True)


        if  check == None:
            error="Invalid login"
            self.render("login.html",error= error)

        else:
            user_id=check.id()
            self.response.headers.add_header('Set-Cookie', 'user_id=%s|%s; Path=/'%(str(user_id), make_pw_hash(str(user_id))))




            self.redirect('/welcome')

class LogOut(Handler):
    def get(self):

        a=""

        self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/'%a)
        self.redirect("/signup")

















app = webapp2.WSGIApplication([('/signup', SignUp),('/welcome', Welcome),
    ('/login',Login),('/logout', LogOut)], debug=True)

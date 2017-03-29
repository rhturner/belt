from __future__ import unicode_literals
from django.contrib import messages

from django.db import models

import re
import bcrypt

emailcheck=re.compile(r'(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)')
namecheck=re.compile(r'^[A-za-z ]{2}[A-za-z ]*')
passwordcheck=re.compile(r'\w{8,}')

class UserManager(models.Manager):
    def login(self, request):
        print "Running login code"
        password=request.POST['password'].encode()
        try:
            user_object=User.objects.get(email=request.POST['email'])
            if bcrypt.hashpw(password.encode(),user_object.pwh.encode())==user_object.pwh:
                request.session['id']=user_object.id
                request.session['name']=user_object.f_name
                request.session['logged_in']=True
                request.session['level']=user_object.level
                return True
        except:
            messages.error(request, "The credentials supplied were not correct.")
            return False

    def validate(self, request):

        password_hash=''

        status=True
        print "Checking Password"
        if request.POST['password'] == request.POST['confirm_password']:
            if not passwordcheck.match(request.POST['password']):
                messages.error(request, "Your password must be at least 8 characters long.")
                status=False
        else:
            messages.error(request, "Your passwords did not match")
            status=False
        print "Checking First Name Length"
        if not namecheck.match(request.POST['f_name']):
            messages.error(request, "Your first name must be 2 characters or longer")
            status=False
        print "Checking Last Name Length"
        if not namecheck.match(request.POST['l_name']):
            messages.error(request, "Your last name must be 2 characters or longer")
            status=False
        print "Checking for email validity"
        if not emailcheck.match(request.POST['email']):
            messages.error(request, "Your email does not appear to be valid")
            status=False
        print "Checking for email uniqueness"
        try:
            User.objects.get(email=request.POST['email'])
            messages.error(request, "Your email is not unique")
            status=False
        except:
            print "Email is valid"
        print "Done with checks...  Returning..."
        if not status:
            return (status, request, password_hash)

        password = request.POST['password']
        password = password.encode()
        password_hash = bcrypt.hashpw(password, bcrypt.gensalt())

        return (status, request, password_hash)

    def validate_update_pw(self, request):
        password_hash=''

        status=True
        print "Checking Password"
        if request.POST['password'] == request.POST['confirm_password']:
            if not passwordcheck.match(request.POST['password']):
                messages.error(request, "Your password must be at least 8 characters long.")
                status=False
        else:
            messages.error(request, "Your passwords did not match")
            status=False


        password = request.POST['password']
        password = password.encode()
        password_hash = bcrypt.hashpw(password, bcrypt.gensalt())
        return status, password_hash

    def validate_update(self, request, id):
        status=True
        print "Checking First Name Length"
        if not namecheck.match(request.POST['f_name']):
            messages.error(request, "Your first name must be 2 characters or longer")
            status=False
        print "Checking Last Name Length"
        if not namecheck.match(request.POST['l_name']):
            messages.error(request, "Your last name must be 2 characters or longer")
            status=False
        print "Checking for email validity"
        if not emailcheck.match(request.POST['email']):
            messages.error(request, "Your email does not appear to be valid")
            status=False
        print "Checking for email uniqueness"
        try:
            user=User.objects.filter(email=request.POST['email']).exclude(id=id)
            if user:
                print "There is no change to the email"
                messages.error(request, "The email entered is not unique")
                status=False
        except:
            print "Email is valid"
        print "Done with checks...  Returning..."

        return status

    def validate_id(self, request, id):
        try:
            user=User.objects.get(id=id)
            return True
        except:
            messages.error(request, "The user ID you presented does not exist in our system")
            return False

class User(models.Model):
    f_name = models.CharField(max_length=20)
    l_name = models.CharField(max_length=20)
    level = models.IntegerField()
    email = models.CharField(max_length=50)
    description = models.TextField(max_length=1000, blank=True)
    pwh = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add = True)
    updated_at = models.DateTimeField(auto_now = True)
    objects = UserManager()

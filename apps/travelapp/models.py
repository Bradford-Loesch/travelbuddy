from __future__ import unicode_literals

from django.db import models

class User(models.Model):
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)
    email = models.CharField(max_length=255)
    password = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

class Trip(models.Model):
    destination = models.CharField(max_length=255)
    description = models.TextField()
    from_date = models.DateField()
    to_date = models.DateField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    User = models.ForeignKey('User', related_name = 'owner')
    Guest = models.ManyToManyField('User', related_name = 'guest')

# class Guest(models.Model):
#     Trip = models.ForeignKey('Trip', relatedname = 'guesttotrip')
#     User = models.ForeignKey('User', relatedname = 'guesttouser')

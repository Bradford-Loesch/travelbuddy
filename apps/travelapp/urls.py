from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^$', views.index),
    url(r'^register$', views.register),
    url(r'^login$', views.login),
    url(r'^logout$', views.logout),
    url(r'^travels$', views.travels),
    url(r'^travels/destination/(?P<id>[0-9]+)$', views.destination),
    url(r'^travels/destination/join/(?P<id>[0-9]+)$', views.newguest),
    url(r'^travels/add$', views.add),
    url(r'^travels/add/new$', views.newtrip),
]

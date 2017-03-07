from django.shortcuts import render, redirect
from django.contrib import messages
import datetime
import models
import bcrypt
import re

def index(request):
    # Test for login
    if not 'login' in request.session:
        request.session['login'] = False
    # If logged in, redirect to main page
    if request.session['login']:
        return redirect('/travels')
    return render(request, 'travelapp/index.html')

def travels(request):
    if not request.session['login']:
        messages.error(request, 'Please log in to access the application.')
        return redirect('/')
    # Get info and pass data
    user = models.User.objects.get(id = request.session['login'])
    yourtrips = models.Trip.objects.filter(User_id = request.session['login'])
    joinedtrips = models.Trip.objects.filter(Guest__id = request.session['login'])
    trips = models.Trip.objects.exclude(User_id = request.session['login']).exclude(Guest__id = request.session['login'])
    context = {
        'user' : user,
        'yourtrips' : yourtrips,
        'joinedtrips' : joinedtrips,
        'trips' : trips,
    }
    return render(request, 'travelapp/travels.html', context)


def destination(request, id):
    if not request.session['login']:
        messages.error(request, 'Please log in to access the application.')
        return redirect('/')
    # Get info and pass data
    user  = models.User.objects.get(id = request.session['login'])
    trip = models.Trip.objects.get(id = id)
    guests = trip.Guest.all()
    joined = False
    if trip.User.id == user.id:
        joined = True
    for guest in guests:
        if guest.id == user.id:
            joined = True
    context = {
        'user' : user,
        'trip' : trip,
        'guests' : guests,
        'joined' : joined,
    }
    return render(request, 'travelapp/destination.html', context)

def add(request):
    if not request.session['login']:
        messages.error(request, 'Please log in to access the application.')
        return redirect('/')
    user  = models.User.objects.get(id = request.session['login'])
    context = {
        'user' : user,
    }
    return render(request, 'travelapp/trip.html', context)

def newtrip(request):
    if request.method == 'POST':
        context = request.POST
        if validtrip(request, context):
            fromdate = datetime.date(int(context['fromdate'][:4]), int(context['fromdate'][5:7]), int(context['fromdate'][8:10]))
            todate = datetime.date(int(context['todate'][:4]), int(context['todate'][5:7]), int(context['todate'][8:10]))
            newtrip = models.Trip(destination = context['destination'], description = context['description'], from_date = fromdate, to_date = todate, User_id = request.session['login'])
            newtrip.save()
        else:
            return redirect('/travels/add')
    return redirect('/travels')

def newguest(request, id):
    user  = models.User.objects.get(id = request.session['login'])
    trip = models.Trip.objects.get(id = id)
    trip.Guest.add(user)
    trip.save()
    return redirect('/travels')

def register(request):
    # Get post data and add to database
    if request.method == 'POST':
        # Get data
        context = request.POST
        #Check if data is valid
        if validate(request, context):
            # Encrypt password and add entry
            hashed = encrypt(context['passworda'])
            new = models.User(first_name = context['first_name'], last_name = context['last_name'], email = context['email'], password = hashed)
            new.save()
            request.session['login'] = new.id
            # Set login to user id and redirect to main page
            return redirect('/travels')
    return redirect('/')

def login(request):
    # Fetch user information and check password
    if request.method == 'POST':
        try:
            user = models.User.objects.get(email = request.POST['loginemail'])
        except:
            messages.error(request, 'Please enter a valid username and password.')
            return redirect('/')
        if comparePass(request.POST['loginpassword'], user.password):
            request.session['login'] = user.id
        else:
            messages.error(request, 'Password did not match.')
            return redirect('/')
    return redirect('/travels')

def logout(request):
    # Show logout message and set request.session variable to false
    messages.error(request, 'You have been logged out.')
    request.session['login'] = False
    return redirect('/')

def encrypt(password):
    # encode and hash password
    password = password.encode()
    hashed = bcrypt.hashpw(password, bcrypt.gensalt())
    return hashed

def comparePass(password, hashed):
    # compare entered and stored passwords
    password = password.encode()
    hashed = hashed.encode()
    if bcrypt.hashpw(password, hashed) == hashed:
        return True
    return False

def validate(request, context):
    # Validation testing
    EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
    failboat = False
    if (len(context['first_name']) < 2):
        messages.error(request, 'First name must be at least 2 characters.')
        failboat = True
    if (len(context['last_name']) < 2):
        messages.error(request, 'First name must be at least 2 characters.')
        failboat = True
    if not EMAIL_REGEX.match(context['email']):
        messages.error(request, 'Email is not valid. Please enter a valid email address.')
        failboat = True
    if (len(context['passworda']) < 8 or len(context['passwordb']) < 8):
        messages.error(request, 'Password must be at least 8 characters')
        failboat = True
    if (context['passworda'] != context['passwordb']):
        messages.error(request, 'Passwords must match')
        failboat = True
    if failboat:
        return False
    return True

def validtrip(request, context):
    failboat = False
    DATE_REGEX = re.compile(r'^\d\d\d\d\-\d\d\-\d\d$')
    if (len(context['destination']) < 2):
        messages.error(request, 'Destination must be at least 2 characters.')
        failboat = True
    if (len(context['description']) < 2):
        messages.error(request, 'Description must be at least 2 characters.')
        failboat = True
    if not DATE_REGEX.match(context['fromdate']):
        messages.error(request, 'Please enter a valid from date.')
        failboat = True
    elif DATE_REGEX.match(context['fromdate']):
        fromdate = datetime.date(int(context['fromdate'][:4]), int(context['fromdate'][5:7]), int(context['fromdate'][8:10]))
    elif fromdate < datetime.date.today():
        messages.error(request, 'Please enter a date on or after today.')
        failboat = True
    if not DATE_REGEX.match(context['todate']):
        messages.error(request, 'Please enter a valid to date.')
        failboat = True
    elif DATE_REGEX.match(context['todate']):
        todate = datetime.date(int(context['todate'][:4]), int(context['todate'][5:7]), int(context['todate'][8:10]))
    elif todate < fromdate:
        messages.error(request, 'Please enter an end date on or after the start date.')
        failboat = True
    if failboat:
        return False
    return True

from django.shortcuts import render, redirect
from django.contrib import messages
from .models import User


def index(request):
    return render(request, 'belt_app/index.html')

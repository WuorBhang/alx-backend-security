from django.shortcuts import render
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django_ratelimit.decorators import ratelimit
from django.contrib.auth import authenticate, login
from django.contrib import messages
from django.shortcuts import redirect
import json


def home(request):
    """Home page view."""
    return render(request, 'ip_tracking/home.html')


@ratelimit(key='ip', rate='5/m', method='POST')
@csrf_exempt
@require_http_methods(["POST"])
def login_view(request):
    """Login view with rate limiting."""
    if request.limited:
        return JsonResponse({
            'error': 'Too many login attempts. Please try again later.'
        }, status=429)
    
    try:
        data = json.loads(request.body)
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return JsonResponse({
                'error': 'Username and password are required'
            }, status=400)
        
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            login(request, user)
            return JsonResponse({
                'message': 'Login successful',
                'user': user.username
            })
        else:
            return JsonResponse({
                'error': 'Invalid credentials'
            }, status=401)
            
    except json.JSONDecodeError:
        return JsonResponse({
            'error': 'Invalid JSON data'
        }, status=400)
    except Exception as e:
        return JsonResponse({
            'error': 'An error occurred during login'
        }, status=500)


@login_required
@ratelimit(key='ip', rate='10/m')
def admin_view(request):
    """Admin view with rate limiting for authenticated users."""
    if request.limited:
        return JsonResponse({
            'error': 'Too many requests. Please try again later.'
        }, status=429)
    
    return render(request, 'ip_tracking/admin.html')

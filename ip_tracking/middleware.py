import logging
from django.http import HttpResponseForbidden
from django.utils.deprecation import MiddlewareMixin
from django.core.cache import cache
from django.conf import settings
from ipware import get_client_ip
from .models import RequestLog, BlockedIP
import requests
import json

logger = logging.getLogger('ip_tracking')


class IPTrackingMiddleware(MiddlewareMixin):
    """
    Middleware to track IP addresses, block blacklisted IPs, and add geolocation data.
    """
    
    def process_request(self, request):
        """Process incoming request to check for blocked IPs and log request data."""
        # Get client IP address
        client_ip, is_routable = get_client_ip(request)
        
        if client_ip is None:
            client_ip = '127.0.0.1'
        
        # Check if IP is blocked
        if self._is_ip_blocked(client_ip):
            logger.warning(f"Blocked request from IP: {client_ip}")
            return HttpResponseForbidden("Access denied: IP address is blocked")
        
        # Store IP in request for use in process_response
        request.client_ip = client_ip
        request.is_routable = is_routable
        
        return None
    
    def process_response(self, request, response):
        """Process response to log request data and add geolocation information."""
        if hasattr(request, 'client_ip'):
            try:
                # Get geolocation data
                country, city = self._get_geolocation_data(request.client_ip)
                
                # Log the request
                RequestLog.objects.create(
                    ip_address=request.client_ip,
                    path=request.path,
                    method=request.method,
                    country=country,
                    city=city,
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                )
                
                logger.info(f"Logged request from {request.client_ip} to {request.path}")
                
            except Exception as e:
                logger.error(f"Error logging request: {e}")
        
        return response
    
    def _is_ip_blocked(self, ip_address):
        """Check if an IP address is in the blocked list."""
        # Check cache first
        cache_key = f"blocked_ip_{ip_address}"
        if cache.get(cache_key) is not None:
            return True
        
        # Check database
        is_blocked = BlockedIP.objects.filter(
            ip_address=ip_address,
            is_active=True
        ).exists()
        
        # Cache the result for 5 minutes
        if is_blocked:
            cache.set(cache_key, True, 300)
        
        return is_blocked
    
    def _get_geolocation_data(self, ip_address):
        """Get geolocation data for an IP address with caching."""
        # Skip geolocation for local IPs
        if ip_address in ['127.0.0.1', '::1'] or ip_address.startswith('192.168.') or ip_address.startswith('10.'):
            return None, None
        
        # Check cache first
        cache_key = f"geolocation_{ip_address}"
        cached_data = cache.get(cache_key)
        
        if cached_data:
            return cached_data.get('country'), cached_data.get('city')
        
        try:
            # Use ipapi.co for geolocation (free tier)
            response = requests.get(f"https://ipapi.co/{ip_address}/json/", timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                country = data.get('country_name')
                city = data.get('city')
                
                # Cache for 24 hours
                cache.set(cache_key, {'country': country, 'city': city}, 86400)
                
                return country, city
            else:
                logger.warning(f"Geolocation API returned status {response.status_code}")
                
        except Exception as e:
            logger.error(f"Error getting geolocation for {ip_address}: {e}")
        
        return None, None

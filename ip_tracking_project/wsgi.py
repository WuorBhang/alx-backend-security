"""
WSGI config for ip_tracking_project project.
"""

import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ip_tracking_project.settings')

application = get_wsgi_application()

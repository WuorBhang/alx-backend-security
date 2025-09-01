# IP Tracking: Security and Analytics

A comprehensive Django application for IP tracking, security monitoring, and analytics.

## Features

### Task 0: Basic IP Logging Middleware ✅
- Middleware that logs IP address, timestamp, and path of every request
- RequestLog model with geolocation support
- Automatic request logging with caching

### Task 1: IP Blacklisting ✅
- BlockedIP model for managing blocked IP addresses
- Middleware integration to block requests from blacklisted IPs
- Management command: `python manage.py block_ip <ip_address> --reason <reason>`

### Task 2: IP Geolocation Analytics ✅
- Extended RequestLog model with country and city fields
- Integration with ipapi.co for geolocation data
- 24-hour caching for geolocation results

### Task 3: Rate Limiting by IP ✅
- django-ratelimit integration
- Different limits for authenticated (10/min) vs anonymous (5/min) users
- Applied to sensitive views (login, admin)

### Task 4: Anomaly Detection ✅
- Celery tasks for hourly suspicious IP detection
- Detects excessive requests (>100/hour), sensitive path access, unusual patterns
- SuspiciousIP model for tracking flagged IPs
- Automatic cleanup of old logs

## Installation

1. Clone the repository
2. Create virtual environment: `python3 -m venv .venv`
3. Activate: `source .venv/bin/activate`
4. Install dependencies: `pip install -r requirements.txt`
5. Run migrations: `python manage.py migrate`
6. Create superuser: `python manage.py createsuperuser`

## Usage

### Starting the Application
```bash
python manage.py runserver
```

### Blocking IP Addresses
```bash
python manage.py block_ip 192.168.1.100 --reason "Suspicious activity"
```

### Running Celery Tasks
```bash
# Start Celery worker
celery -A ip_tracking_project worker -l info

# Start Celery beat scheduler
celery -A ip_tracking_project beat -l info
```

### Admin Interface
Access Django admin at `/admin/` to view:
- Request logs with geolocation data
- Blocked IP addresses
- Suspicious IP detections

## Configuration

### Rate Limiting
- Anonymous users: 5 requests/minute
- Authenticated users: 10 requests/minute

### Anomaly Detection Thresholds
- Excessive requests: >100 requests/hour
- Sensitive path access: >10 accesses/hour to /admin/, /login/
- Unusual patterns: >20 different paths accessed/hour

### Geolocation
- Uses ipapi.co API (free tier)
- 24-hour caching for performance
- Skips local IP addresses

## Models

### RequestLog
- ip_address: Client IP
- timestamp: Request time
- path: Request path
- country/city: Geolocation data
- method: HTTP method
- user_agent: Browser info

### BlockedIP
- ip_address: Blocked IP
- reason: Blocking reason
- is_active: Active status
- created_at: Block time

### SuspiciousIP
- ip_address: Flagged IP
- reason: Detection reason
- request_count: Number of requests
- is_resolved: Resolution status
- detected_at: Detection time

## Security Features

- IP blocking with cache optimization
- Rate limiting to prevent abuse
- Anomaly detection for suspicious patterns
- Automatic log cleanup (30 days retention)
- Privacy-conscious geolocation handling

## Monitoring

The application logs all activities to `ip_tracking.log` and provides:
- Real-time IP tracking
- Geographic request distribution
- Suspicious activity alerts
- Performance metrics

## Compliance

- GDPR/CCPA compliant with data retention policies
- Transparent logging practices
- User privacy protection
- Ethical IP tracking implementation

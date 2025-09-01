from celery import shared_task
from django.utils import timezone
from datetime import timedelta
from django.db.models import Count
from .models import RequestLog, SuspiciousIP
import logging

logger = logging.getLogger('ip_tracking')


@shared_task
def detect_suspicious_ips():
    """
    Celery task to detect suspicious IP addresses based on request patterns.
    Runs hourly to analyze request logs and flag suspicious behavior.
    """
    logger.info("Starting suspicious IP detection task")
    
    # Get the time range for the last hour
    one_hour_ago = timezone.now() - timedelta(hours=1)
    
    try:
        # Detect IPs with excessive requests (>100 requests/hour)
        excessive_requests = (
            RequestLog.objects
            .filter(timestamp__gte=one_hour_ago)
            .values('ip_address')
            .annotate(request_count=Count('id'))
            .filter(request_count__gt=100)
        )
        
        for item in excessive_requests:
            ip_address = item['ip_address']
            request_count = item['request_count']
            
            # Check if already flagged
            if not SuspiciousIP.objects.filter(
                ip_address=ip_address,
                is_resolved=False
            ).exists():
                SuspiciousIP.objects.create(
                    ip_address=ip_address,
                    reason=f"Excessive requests: {request_count} requests in the last hour",
                    request_count=request_count
                )
                logger.warning(f"Flagged suspicious IP {ip_address} for excessive requests: {request_count}")
        
        # Detect IPs accessing sensitive paths
        sensitive_paths = ['/admin/', '/login/', '/api/admin/']
        
        for path in sensitive_paths:
            suspicious_access = (
                RequestLog.objects
                .filter(
                    timestamp__gte=one_hour_ago,
                    path__icontains=path
                )
                .values('ip_address')
                .annotate(access_count=Count('id'))
                .filter(access_count__gt=10)  # More than 10 accesses to sensitive path
            )
            
            for item in suspicious_access:
                ip_address = item['ip_address']
                access_count = item['access_count']
                
                # Check if already flagged for this reason
                if not SuspiciousIP.objects.filter(
                    ip_address=ip_address,
                    reason__icontains=f"accessing sensitive path {path}",
                    is_resolved=False
                ).exists():
                    SuspiciousIP.objects.create(
                        ip_address=ip_address,
                        reason=f"Accessing sensitive path {path}: {access_count} times in the last hour",
                        request_count=access_count
                    )
                    logger.warning(f"Flagged suspicious IP {ip_address} for accessing sensitive path {path}: {access_count}")
        
        # Detect IPs with unusual request patterns (multiple different paths)
        unusual_patterns = (
            RequestLog.objects
            .filter(timestamp__gte=one_hour_ago)
            .values('ip_address')
            .annotate(unique_paths=Count('path', distinct=True))
            .filter(unique_paths__gt=20)  # More than 20 different paths
        )
        
        for item in unusual_patterns:
            ip_address = item['ip_address']
            unique_paths = item['unique_paths']
            
            # Check if already flagged for this reason
            if not SuspiciousIP.objects.filter(
                ip_address=ip_address,
                reason__icontains="unusual request pattern",
                is_resolved=False
            ).exists():
                SuspiciousIP.objects.create(
                    ip_address=ip_address,
                    reason=f"Unusual request pattern: {unique_paths} different paths accessed in the last hour",
                    request_count=unique_paths
                )
                logger.warning(f"Flagged suspicious IP {ip_address} for unusual request pattern: {unique_paths} different paths")
        
        logger.info("Suspicious IP detection task completed successfully")
        
    except Exception as e:
        logger.error(f"Error in suspicious IP detection task: {e}")
        raise


@shared_task
def cleanup_old_logs():
    """
    Cleanup task to remove old request logs to manage database size.
    Keeps logs for 30 days by default.
    """
    logger.info("Starting log cleanup task")
    
    try:
        # Delete logs older than 30 days
        thirty_days_ago = timezone.now() - timedelta(days=30)
        deleted_count = RequestLog.objects.filter(timestamp__lt=thirty_days_ago).delete()[0]
        
        logger.info(f"Deleted {deleted_count} old request logs")
        
        # Also cleanup resolved suspicious IPs older than 7 days
        seven_days_ago = timezone.now() - timedelta(days=7)
        deleted_suspicious = SuspiciousIP.objects.filter(
            is_resolved=True,
            detected_at__lt=seven_days_ago
        ).delete()[0]
        
        logger.info(f"Deleted {deleted_suspicious} resolved suspicious IP records")
        
    except Exception as e:
        logger.error(f"Error in log cleanup task: {e}")
        raise

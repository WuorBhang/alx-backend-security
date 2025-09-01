from django.db import models
from django.utils import timezone


class RequestLog(models.Model):
    """Model to store request logs with IP address, timestamp, and path."""
    ip_address = models.GenericIPAddressField()
    timestamp = models.DateTimeField(default=timezone.now)
    path = models.CharField(max_length=255)
    country = models.CharField(max_length=100, blank=True, null=True)
    city = models.CharField(max_length=100, blank=True, null=True)
    user_agent = models.TextField(blank=True, null=True)
    method = models.CharField(max_length=10, default='GET')
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['ip_address']),
            models.Index(fields=['timestamp']),
            models.Index(fields=['path']),
        ]
    
    def __str__(self):
        return f"{self.ip_address} - {self.path} - {self.timestamp}"


class BlockedIP(models.Model):
    """Model to store blocked IP addresses."""
    ip_address = models.GenericIPAddressField(unique=True)
    created_at = models.DateTimeField(default=timezone.now)
    reason = models.TextField(blank=True, null=True)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['ip_address']),
            models.Index(fields=['is_active']),
        ]
    
    def __str__(self):
        return f"Blocked: {self.ip_address}"


class SuspiciousIP(models.Model):
    """Model to store suspicious IP addresses detected by anomaly detection."""
    ip_address = models.GenericIPAddressField()
    reason = models.TextField()
    detected_at = models.DateTimeField(default=timezone.now)
    request_count = models.IntegerField(default=0)
    is_resolved = models.BooleanField(default=False)
    
    class Meta:
        ordering = ['-detected_at']
        indexes = [
            models.Index(fields=['ip_address']),
            models.Index(fields=['detected_at']),
            models.Index(fields=['is_resolved']),
        ]
    
    def __str__(self):
        return f"Suspicious: {self.ip_address} - {self.reason}"

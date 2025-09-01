from django.contrib import admin
from .models import RequestLog, BlockedIP, SuspiciousIP


@admin.register(RequestLog)
class RequestLogAdmin(admin.ModelAdmin):
    list_display = ['ip_address', 'path', 'method', 'country', 'city', 'timestamp']
    list_filter = ['method', 'country', 'timestamp']
    search_fields = ['ip_address', 'path', 'country', 'city']
    readonly_fields = ['timestamp']
    date_hierarchy = 'timestamp'
    ordering = ['-timestamp']


@admin.register(BlockedIP)
class BlockedIPAdmin(admin.ModelAdmin):
    list_display = ['ip_address', 'reason', 'is_active', 'created_at']
    list_filter = ['is_active', 'created_at']
    search_fields = ['ip_address', 'reason']
    readonly_fields = ['created_at']
    date_hierarchy = 'created_at'
    ordering = ['-created_at']


@admin.register(SuspiciousIP)
class SuspiciousIPAdmin(admin.ModelAdmin):
    list_display = ['ip_address', 'reason', 'request_count', 'is_resolved', 'detected_at']
    list_filter = ['is_resolved', 'detected_at']
    search_fields = ['ip_address', 'reason']
    readonly_fields = ['detected_at']
    date_hierarchy = 'detected_at'
    ordering = ['-detected_at']
    
    actions = ['mark_as_resolved']
    
    def mark_as_resolved(self, request, queryset):
        updated = queryset.update(is_resolved=True)
        self.message_user(request, f'{updated} suspicious IP records marked as resolved.')
    mark_as_resolved.short_description = "Mark selected suspicious IPs as resolved"

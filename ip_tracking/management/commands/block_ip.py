from django.core.management.base import BaseCommand, CommandError
from ip_tracking.models import BlockedIP


class Command(BaseCommand):
    help = 'Add an IP address to the blocked list'

    def add_arguments(self, parser):
        parser.add_argument('ip_address', type=str, help='IP address to block')
        parser.add_argument('--reason', type=str, help='Reason for blocking the IP')

    def handle(self, *args, **options):
        ip_address = options['ip_address']
        reason = options.get('reason', 'Manually blocked')

        try:
            # Check if IP is already blocked
            if BlockedIP.objects.filter(ip_address=ip_address).exists():
                self.stdout.write(
                    self.style.WARNING(f'IP address {ip_address} is already blocked')
                )
                return

            # Create new blocked IP entry
            blocked_ip = BlockedIP.objects.create(
                ip_address=ip_address,
                reason=reason
            )

            self.stdout.write(
                self.style.SUCCESS(f'Successfully blocked IP address: {ip_address}')
            )
            self.stdout.write(f'Reason: {reason}')
            self.stdout.write(f'Created at: {blocked_ip.created_at}')

        except Exception as e:
            raise CommandError(f'Error blocking IP address: {e}')

from django.core.management.base import BaseCommand
from App1.models import SuperAdmin

class Command(BaseCommand):
    help = 'Initialize super-admin credentials'

    def handle(self, *args, **kwargs):
        superadmin_email = 'anjali@gmail.com'
        superadmin_password = 'anjali123'

        # Check if super-admin already exists
        superadmin_exists = SuperAdmin.objects.filter(email=superadmin_email).exists()

        if not superadmin_exists:
            # Create super-admin if it doesn't exist
            superadmin = SuperAdmin.objects.create(
                superadmin_name='Anjali',
                email=superadmin_email,
                password=superadmin_password  # Ensure you hash the password if required
            )
            self.stdout.write(self.style.SUCCESS('Super-admin created successfully'))
        else:
            self.stdout.write(self.style.WARNING('Super-admin already exists'))

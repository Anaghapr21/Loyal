# Generated by Django 4.2.7 on 2023-12-13 11:38

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("App1", "0055_timecycle_timecycleday_allocation"),
    ]

    operations = [
        migrations.RenameField(
            model_name="passwordresettoken",
            old_name="token",
            new_name="otp",
        ),
    ]
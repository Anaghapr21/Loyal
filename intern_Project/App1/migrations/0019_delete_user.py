# Generated by Django 4.2.7 on 2023-12-07 04:34

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("App1", "0018_user"),
    ]

    operations = [
        migrations.DeleteModel(
            name="User",
        ),
    ]
# Generated by Django 4.2.7 on 2023-12-12 14:42

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("App1", "0052_delete_timecycleday"),
    ]

    operations = [
        migrations.CreateModel(
            name="TimeCycleDay",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("day", models.DateField()),
                (
                    "time_cycle",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="App1.timecycle"
                    ),
                ),
            ],
        ),
    ]

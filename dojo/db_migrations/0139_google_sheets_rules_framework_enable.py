# Generated by Django 3.2.9 on 2021-12-10 02:49

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dojo', '0138_remove_authorized_users'),
    ]

    operations = [
        migrations.AddField(
            model_name='system_settings',
            name='enable_rules_framework',
            field=models.BooleanField(default=False, help_text='With this setting turned off, the rules framwork will be disabled in the user interface.', verbose_name='Enable Rules Framework'),
        ),
        migrations.AlterField(
            model_name='system_settings',
            name='enable_google_sheets',
            field=models.BooleanField(default=False, help_text='With this setting turned off, the Google sheets integration will be disabled in the user interface.', verbose_name='Enable Google Sheets Integration'),
        ),
    ]

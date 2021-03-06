# -*- coding: utf-8 -*-
# Generated by Django 1.10.2 on 2016-10-24 21:08
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('travelapp', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='trip',
            name='Guest',
            field=models.ManyToManyField(related_name='guest', to='travelapp.User'),
        ),
        migrations.AlterField(
            model_name='trip',
            name='User',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='owner', to='travelapp.User'),
        ),
    ]

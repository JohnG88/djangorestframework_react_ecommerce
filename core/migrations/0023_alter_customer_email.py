# Generated by Django 4.2.1 on 2024-10-20 23:08

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0022_order_all_order_items_returned'),
    ]

    operations = [
        migrations.AlterField(
            model_name='customer',
            name='email',
            field=models.CharField(blank=True, max_length=200, null=True, unique=True),
        ),
    ]

# Generated by Django 4.2.1 on 2023-09-15 03:31

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0006_order_billing_address_order_first_name_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='orderitem',
            name='item_returned',
            field=models.BooleanField(default=False),
        ),
    ]

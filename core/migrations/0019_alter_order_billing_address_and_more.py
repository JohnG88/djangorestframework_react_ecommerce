# Generated by Django 4.2.1 on 2023-10-22 02:20

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0018_order_billing_address_order_shipping_address'),
    ]

    operations = [
        migrations.AlterField(
            model_name='order',
            name='billing_address',
            field=models.CharField(blank=True, max_length=500, null=True),
        ),
        migrations.AlterField(
            model_name='order',
            name='shipping_address',
            field=models.CharField(blank=True, max_length=500, null=True),
        ),
    ]

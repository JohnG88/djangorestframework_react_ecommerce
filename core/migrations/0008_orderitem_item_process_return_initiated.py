# Generated by Django 4.2.1 on 2023-09-15 03:32

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0007_orderitem_item_returned'),
    ]

    operations = [
        migrations.AddField(
            model_name='orderitem',
            name='item_process_return_initiated',
            field=models.BooleanField(default=False),
        ),
    ]
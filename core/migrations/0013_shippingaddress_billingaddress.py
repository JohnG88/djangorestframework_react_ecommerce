# Generated by Django 4.2.1 on 2023-10-20 00:44

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0012_alter_order_billing_address_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='ShippingAddress',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('first_name', models.CharField(max_length=300)),
                ('last_name', models.CharField(max_length=300)),
                ('street_address', models.CharField(max_length=300)),
                ('apt', models.CharField(max_length=300)),
                ('city', models.CharField(max_length=300)),
                ('state', models.CharField(max_length=300)),
                ('zipcode', models.CharField(max_length=300)),
                ('customer', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='core.customer')),
            ],
        ),
        migrations.CreateModel(
            name='BillingAddress',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('first_name', models.CharField(max_length=300)),
                ('last_name', models.CharField(max_length=300)),
                ('street_address', models.CharField(max_length=300)),
                ('apt', models.CharField(max_length=300)),
                ('city', models.CharField(max_length=300)),
                ('state', models.CharField(max_length=300)),
                ('zipcode', models.CharField(max_length=300)),
                ('customer', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='core.customer')),
            ],
        ),
    ]

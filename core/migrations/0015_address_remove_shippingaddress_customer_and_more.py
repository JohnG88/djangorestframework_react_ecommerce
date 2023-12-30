# Generated by Django 4.2.1 on 2023-10-22 00:51

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0014_alter_billingaddress_customer_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='Address',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('is_active', models.BooleanField(default=False)),
                ('address_type', models.CharField(max_length=10)),
                ('first_name', models.CharField(max_length=300)),
                ('last_name', models.CharField(max_length=300)),
                ('street_address', models.CharField(max_length=300)),
                ('apt', models.CharField(max_length=300)),
                ('city', models.CharField(max_length=300)),
                ('state', models.CharField(max_length=300)),
                ('zipcode', models.CharField(max_length=300)),
                ('customer', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='core.customer')),
            ],
        ),
        migrations.RemoveField(
            model_name='shippingaddress',
            name='customer',
        ),
        migrations.DeleteModel(
            name='BillingAddress',
        ),
        migrations.DeleteModel(
            name='ShippingAddress',
        ),
        migrations.AlterField(
            model_name='order',
            name='billing_address',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='billing_address', to='core.address'),
        ),
        migrations.AlterField(
            model_name='order',
            name='shipping_address',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='shipping_address', to='core.address'),
        ),
    ]
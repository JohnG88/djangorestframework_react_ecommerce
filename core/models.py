from django.db import models
from django.contrib.auth.models import User
from django.core.validators import MaxValueValidator, FileExtensionValidator
from decimal import Decimal

# Create your models here.

class Customer(models.Model):
    user = models.OneToOneField(User, null=True, blank=True, on_delete=models.CASCADE)
    name = models.CharField(max_length=200, null=True, blank=True)
    email = models.CharField(max_length=200, null=True, blank=True)
    device = models.CharField(max_length=200, null=True, blank=True)
    customer_stripe_id = models.CharField(max_length=300, null=True, blank=True)
    avatar = models.ImageField(default='avatar.png', upload_to="avatar_image", validators=[FileExtensionValidator(['png', 'jpg', 'jpeg'])])

    def __str__(self):
        return f"{self.device}"

class Product(models.Model):
    name = models.CharField(max_length=200)
    image = models.ImageField(default='product.png', upload_to="item_images", validators=[FileExtensionValidator(['png', 'jpg', 'jpeg'])])
    description = models.TextField(max_length=1000)
    price = models.DecimalField(max_digits=6, decimal_places=2, default=Decimal('0.00'))
    quantity = models.PositiveIntegerField(default=0, validators=[MaxValueValidator(999)])
    quantity_limit = models.PositiveIntegerField(default=0)
    sold = models.PositiveIntegerField(default=0)

    def __str__(self):
        return f"{self.name}"
    
    def get_image(self, obj):
        if obj.image:
            # Return the relative URL directly if it exists
            return obj.image.url
        return None

class Address(models.Model):
    customer = models.ForeignKey(Customer, on_delete=models.CASCADE, null=True, blank=True)
    is_active = models.BooleanField(default=False)
    address_type = models.CharField(max_length=10)
    first_name = models.CharField(max_length=300)
    last_name = models.CharField(max_length=300)
    street_address = models.CharField(max_length=300)
    apt = models.CharField(max_length=300)
    city = models.CharField(max_length=300)
    state = models.CharField(max_length=300)
    zipcode = models.CharField(max_length=300)


class Order(models.Model):
    customer = models.ForeignKey(Customer, on_delete=models.SET_NULL, null=True, blank=True)
    date_ordered = models.DateTimeField(auto_now_add=True)
    complete = models.BooleanField(default=False)
    stripe_charge_id = models.CharField(max_length=300, blank=True, null=True)
    first_name = models.CharField(max_length=300, blank=True, null=True)
    last_name = models.CharField(max_length=300, blank=True, null=True)
    user_email = models.EmailField(max_length=200, blank=True, null=True)
    shipping_address = models.ForeignKey(Address, related_name='shipping_address', on_delete=models.SET_NULL, blank=True, null=True)
    billing_address = models.ForeignKey(Address,related_name='billing_address', on_delete=models.SET_NULL, blank=True, null=True)
    all_order_items_returned = models.BooleanField(default=False)

    #shipping_address = models.CharField(max_length=500, blank=True, null=True)
    #billing_address = models.CharField(max_length=500, blank=True, null=True)
    

    @property
    def get_cart_total(self):
        orderitems = self.orderitem_set.all()
        total = sum([item.get_total for item in orderitems])

        return total
    
    @property
    def get_cart_items(self):
        orderitems = self.orderitem_set.all()
        total = sum([item.quantity for item in orderitems])
        return total
    
    def __str__(self):
        return f"Order id: {self.id}"

""" 
class ShippingAddress(models.Model):
    customer = models.ForeignKey(Customer, on_delete=models.CASCADE, null=True, blank=True)
    first_name = models.CharField(max_length=300)
    last_name = models.CharField(max_length=300)
    street_address = models.CharField(max_length=300)
    apt = models.CharField(max_length=300)
    city = models.CharField(max_length=300)
    state = models.CharField(max_length=300)
    zipcode = models.CharField(max_length=300)

class BillingAddress(models.Model):
    customer = models.ForeignKey(Customer, on_delete=models.CASCADE, null=True, blank=True)
    first_name = models.CharField(max_length=300)
    last_name = models.CharField(max_length=300)
    street_address = models.CharField(max_length=300)
    apt = models.CharField(max_length=300)
    city = models.CharField(max_length=300)
    state = models.CharField(max_length=300)
    zipcode = models.CharField(max_length=300)
"""

class OrderItem(models.Model):
    product = models.ForeignKey(Product, on_delete=models.SET_NULL, null=True)
    order = models.ForeignKey(Order, on_delete=models.SET_NULL, null=True)
    quantity = models.PositiveIntegerField(default=0, null=True, blank=True)
    item_amount_returning = models.PositiveIntegerField(default=0)
    item_process_return_initiated = models.BooleanField(default=False)
    item_returned = models.BooleanField(default=False)
    all_items_returned = models.BooleanField(default=False)
    partial_returned = models.BooleanField(default=False)

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)

        # Check if all items for the order are returned
        all_items_returned = self.order.orderitem_set.filter(all_items_returned=False).count() == 0

        # Update the order's all_order_items_returned field
        self.order.all_order_items_returned = all_items_returned
        self.order.save()

    @property
    def get_total(self):
        total = self.product.price * self.quantity
        return total
    
    def __str__(self):
        return f"{self.id}"
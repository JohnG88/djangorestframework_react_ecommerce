from django.contrib import admin
from .models import Customer, Product, Order, OrderItem, Address
# Register your models here.

class OrderAdmin(admin.ModelAdmin):
    list_display = ('id', 'date_ordered', 'customer', 'complete', 'get_cart_total')
    search_fields = ('customer__user__username', 'customer__user__email')  # Add search fields as needed

admin.site.register(Customer)
admin.site.register(Product)
admin.site.register(Order, OrderAdmin)
admin.site.register(OrderItem)
admin.site.register(Address)
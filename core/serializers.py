from django.contrib.auth.models import User

from rest_framework import serializers

from .models import Customer, Product, Order, OrderItem, Address

class RelativeImageURLField(serializers.ImageField):
    def to_representation(self, value):
        request = self.context.get('request', None)
        if request and value:
            return request.build_absolute_uri(value.url)
        return super().to_representation(value)

'''
class RelativeProductImageURLField(serializers.Field):
    def to_representation(self, value):
        request = self.context.get('request')
        if request is not None and value.image:
            return request.build_absolute_uri(value.image.url)
        return None
'''


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email']

class CustomerSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    
    #user = serializers.PrimaryKeyRelatedField(queryset=User.objects.all(), allow_null=True, required=False)
    #logged_in_user = serializers.SerializerMethodField()

    #def get_logged_in_user(self, obj):
    #    return self.context['request'].user.id

    class Meta:
        model = Customer
        fields = ['id', 'user', 'name', 'email', 'device']

class ProductSerializer(serializers.ModelSerializer):
    #image = RelativeImageURLField()
    image = serializers.SerializerMethodField()

    class Meta:
        model = Product
        fields = ['id', 'name', 'image', 'description', 'price', 'quantity', 'quantity_limit', 'sold']
        
        '''
        def get_image_url(self, obj):
            if obj.image:
                return obj.image.url
            return None
        '''

        #read_only_fields = ('image',)
    
    
    def get_image(self, obj):
        request = self.context.get('request', None)
        if request and obj.image:
            # Build the absolute URL to the image based on the request
            return request.build_absolute_uri(obj.image.url)
        return None


class OrderItemSerializer(serializers.ModelSerializer):
    product_detail = ProductSerializer(source='product', read_only=True)
    class Meta:
        model = OrderItem
        fields = ['id', 'product_detail', 'order', 'quantity', 'item_amount_returning', 'item_process_return_initiated', 'item_returned', 'all_items_returned', 'partial_returned']

    '''
    def to_representation(self, instance):
        representation = super().to_representation(instance)

        # Generate the full image URL based on the request object
        request = self.context.get('request')
        if request:
            product = instance.product
            if product.image:
                representation['product']['image'] = request.build_absolute_uri(product.image.url)

        return representation
    '''
'''
class OrderItemSerializer(serializers.ModelSerializer):
    product_detail = RelativeProductImageURLField(source='product', read_only=True)

    class Meta:
        model = OrderItem
        fields = ['id', 'product_detail', 'order', 'quantity', 'item_amount_returning', 'item_process_return_initiated', 'item_returned', 'all_items_returned', 'partial_returned']


'''

class AddressSerializer(serializers.ModelSerializer):
    customer_detail = CustomerSerializer(source='customer', read_only=True)
    address_type = serializers.ChoiceField(choices=['billing', 'shipping'])

    class Meta:
        model = Address
        fields = ('id', 'customer', 'customer_detail', 'is_active', 'address_type', 'first_name', 'last_name', 'street_address', 'apt', 'city', 'state', 'zipcode')

class OrderSerializer(serializers.ModelSerializer):
    order_items = serializers.SerializerMethodField(read_only=True)

    customer_detail = CustomerSerializer(source='customer', read_only=True)

    get_cart_total = serializers.CharField(required=False)

    billing_address = AddressSerializer(read_only=True)

    shipping_address = AddressSerializer(read_only=True)

    class Meta:
        model = Order
        fields = ['id','customer_detail', 'order_items', 'date_ordered', 'complete', 'first_name', 'last_name', 'get_cart_total', 'shipping_address', 'billing_address', 'all_order_items_returned']
    
    
    def get_order_items(self, obj):
        items = obj.orderitem_set.all()
        context = {'request': self.context.get('request')}
        serializer = OrderItemSerializer(items, many=True, context=context)
        return serializer.data
    
'''
class OrderSerializer(serializers.ModelSerializer):
    order_items = OrderItemSerializer(many=True, read_only=True)

    customer_detail = CustomerSerializer(source='customer', read_only=True)

    class Meta:
        model = Order
        fields = ['id', 'customer_detail', 'order_items', 'date_ordered', 'complete']
'''

'''
class ShippingAddressSerializer(serializers.ModelSerializer):
    customer_detail = CustomerSerializer(source='customer', read_only=True)

    class Meta:
        model = ShippingAddress
        fields = ('customer', 'customer_detail', 'first_name', 'last_name', 'street_address', 'apt', 'city', 'state', 'zipcode')

class BillingAddressSerializer(serializers.ModelSerializer):
    customer_detail = CustomerSerializer(source='customer', read_only=True)

    class Meta:
        model = BillingAddress
        fields = ('customer', 'customer_detail', 'first_name', 'last_name', 'street_address', 'apt', 'city', 'state', 'zipcode')
'''    



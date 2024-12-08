import datetime
import stripe
import uuid

#from datetime import datetime

from django.conf import settings
from django.contrib.auth import authenticate, login, logout, get_user_model 
from django.contrib.auth.models import AnonymousUser, User 
from django.contrib.auth.password_validation import validate_password
from django.contrib.sessions.models import Session
from django.core.exceptions import ObjectDoesNotExist, ValidationError as DjangoValidationError
from django.core.mail import send_mail
from django.http import HttpResponseRedirect
from django.template.loader import render_to_string
from django.utils import timezone
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse, HttpResponse

#from knox.views import LoginView as KnoxLoginView

from rest_framework import status, viewsets, serializers
from rest_framework.decorators import api_view, permission_classes
from rest_framework.exceptions import ValidationError as DRFValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response


from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView

from .models import Customer, Product, Order, OrderItem, Address
from .serializers import CustomerSerializer, ProductSerializer, OrderSerializer, OrderItemSerializer, AddressSerializer, ResetPasswordSerializer, PasswordResetConfirmSerializer

stripe.api_key = settings.STRIPE_SECRET_KEY

# Get user
# User = get_user_model()

# Create your views here.


""" ---OG View ---"""
# class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
#     email = serializers.EmailField()

#     def validate_email(self, value):
#         try:
#             # Check if a user with the given email exists
#             user = User.objects.get(email=value)
#         except User.DoesNotExist:
#             # Raise a validation error if the user with this email does not exist
#             raise serializers.ValidationError("User with this email does not exist.")
#         return value

    # @classmethod
    # def get_token(cls, user):
    #     token = super().get_token(user)
    #     token['username'] = user.username

    #     return token

""" ---Chatgpt version---"""
class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    email = serializers.EmailField()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Remove the `username` field if it's present in the fields
        self.fields.pop('username', None)

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')

        # print(f"validating with email: {email} and password: {password}")

        # Authenticate user by email
        UserModel = get_user_model()

        try:
            user = UserModel.objects.get(email=email)
            # print(f"user {user}")
        except UserModel.DoesNotExist:
            raise serializers.ValidationError({"detail": "Invalid credentials"})

        # Check password
        if not user.check_password(password):
            raise serializers.ValidationError({"detail": "Invalid credentials"})

        # Set the user on the serializer
        self.user = user

        # Create token without needing username
        refresh = self.get_token(user)
        data = {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }

        # Add any extra fields (like email) to the token response
        data['username'] = user.username

        return data
    
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token['username'] = user.username  # Add email to the token
        return token
    
"""--- Second ChatGPT version to fix login ---"""
class MyTokenObtainPairView(TokenObtainPairView):
    serializer_class = MyTokenObtainPairSerializer

    def post(self, request, *args, **kwargs):
        # Log the incoming request data
        # print(f"Incoming request data: {request.data}")

        # Manually serialize the request data (email and password)
        serializer = self.get_serializer(data=request.data)

        try:
            # Validate the serializer and trigger authentication
            serializer.is_valid(raise_exception=True)

            # Get the validated token data
            data = serializer.validated_data
            # print(f"Validated data: {data}")
            
            # Create the response
            response = Response(data, status=status.HTTP_200_OK)

            # After successful authentication, handle cookie setting
            user = serializer.user
            device_number = str(user.customer.device)

            # Check if 'my_cookie' is present
            my_cookie_value = request.COOKIES.get("my_cookie")

            # If no cookie is present, set it to the user's device number
            if my_cookie_value is None:
                response.set_cookie('my_cookie', device_number, secure=True, samesite='None', path='/')

            return response

        except serializers.ValidationError as e:
            # print(f"Validation error: {e.detail}")
            return Response({"detail": "Invalid credentials"}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            # print(f"Unexpected error: {e}")
            return Response({"detail": "An unexpected error occurred"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        # OG Response for username/password login
        """
        user = authenticate(request, email=email, password=password)

        print(f"login user {user}")

        if user is not None:
            device_number = str(user.customer.device)

            # Check if the 'my_cookie' is present
            my_cookie_value = request.COOKIES.get("my_cookie")

            # Use the usual login process
            response = super().post(request, *args, **kwargs)

            if my_cookie_value is None:
                # If no cookie, set the cookie to the user's device number
                response.set_cookie('my_cookie', device_number, secure=True, samesite='None', path='/')
            
            return response
        else:
            return Response({"detail": "Invalid credentials"}, status=400)
        """


"""--- ChatGPT MyTokenObtainPairView function ---"""
# class MyTokenObtainPairView(TokenObtainPairView):
#     serializer_class = MyTokenObtainPairSerializer

#     def post(self, request, *args, **kwargs):
#         # Authenticate the user with provided credentials
#         user = authenticate(username=request.data.get('username'), password=request.data.get('password'))

#         if user is not None:
#             # Retrieve the device number associated with the user
#             device_number = str(user.customer.device)  # Assuming 'device_number' is the field in your model
#             print(f"Logged in user device number: {device_number}")

#             # Check if the 'my_cookie' is present
#             my_cookie_value = request.COOKIES.get("my_cookie")

#             if my_cookie_value is None:
#                 # If no cookie, set the cookie to the user's device number
#                 response = Response({"detail": "Login successful, cookie set"})
#                 response.set_cookie('my_cookie', device_number, secure=True, samesite='None', path='/')
#                 return response
#             else:
#                 # If cookie is present, proceed with usual login
#                 response = super().post(request, *args, **kwargs)
#                 return response
#         else:
#             return Response({"detail": "Invalid credentials"}, status=400)



"""--- OG MyTokenObtainPairView function ---"""  
# class MyTokenObtainPairView(TokenObtainPairView):
#     serializer_class = MyTokenObtainPairSerializer

#     def post(self, request, *args, **kwargs):
#         response = super().post(request, *args, **kwargs)
        
#         if request.user.is_authenticated:
#             # If the user is authenticated, retrieve the UUID of the logged-in user
#             user_uuid = str(request.user.customer.uuid)  # Assuming 'uuid' is the field storing UUID in your user model
#             print(f"logged in user uuid {user_uuid}")
            
#             # Set the user UUID as the value of the 'my_cookie' cookie
#             response.set_cookie('my_cookie', user_uuid, secure=True, samesite='None', path='/')

#         return response

'''Removes cookie on login'''

# class MyTokenObtainPairView(TokenObtainPairView):
#     serializer_class = MyTokenObtainPairSerializer

#     def post(self, request, *args, **kwargs):
#         response = super().post(request, *args, **kwargs)

#         #response.delete_cookie('my_cookie')
        
        
#         # Create a new cookie to delete the existing one
#         expiration_date = datetime.datetime.now() - datetime.timedelta(days=1)
#         response.set_cookie('my_cookie', '', expires=expiration_date, secure=True, samesite='None', path='/')

#         return response

#def HomeViewSet(viewsets.ModelViewSet):

"""
class LoginView(KnoxLoginView):
    #permission_classes = []

    def post(self, request, format=None):
        username = request.data.get('username')
        password = request.data.get('password')
        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            #return super().post(request, format=None)
        return Response({'detail': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
"""

@api_view(['POST'])
def password_reset_view(request):
    if request.method == 'POST':
        serializer = ResetPasswordSerializer(data=request.data, context={'request': request})

        if serializer.is_valid():
            serializer.save()
            return Response({'detail': 'Password reset email has been sent.'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

@api_view(['POST'])
def password_reset_confirm_view(request):
    serializer = PasswordResetConfirmSerializer(data=request.data)

    if serializer.is_valid():
        serializer.save()
        return Response({'detail': 'Password has been reset successfully.'}, status=status.HTTP_200_OK)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
def logout_view(request):
    logout(request)
    response = HttpResponseRedirect('/')
    response.delete_cookie('my_cookie')
    return response

@api_view(['POST'])
def register_user(request):
    if request.method == 'POST':
        data = request.data

        username = data['username']
        email = data['email']
        password = data['password']

        # Validate password complexity using Django's built-in password validators
        try:
            validate_password(password)
        except DjangoValidationError as e:
            # return Response({"error": e.messages}, status=status.HTTP_400_BAD_REQUEST)'
            raise DRFValidationError(e.messages)


        #create new user
        user = User.objects.create_user(username=username, password=password, email=email)

        device = request.COOKIES.get('my_cookie')
        customer, created = Customer.objects.get_or_create(device=device)

        customer.user = user
        customer.save()

        response = Response({'message': 'User created successfully'}, status=status.HTTP_201_CREATED)

        "--- OG getting rid of cookie on registration ---"
        # Create a new cookie to delete the existing one
        # expiration_date = datetime.datetime.now() - datetime.timedelta(days=1)
        # response.set_cookie('my_cookie', '', expires=expiration_date, secure=True, samesite='None', path='/')

        '''
        # Delete the cookie in the response
        response = Response({'message': 'User created successfully'}, status=status.HTTP_201_CREATED)
        response.delete_cookie('my_cookie', path='/', secure=True, samesite='None')
        '''
        '''
        return Response({'message': 'User created successfully'}, status=status.HTTP_201_CREATED)
        '''

        return response
        
@api_view(['GET'])
def get_user(request):
    if request.user.is_authenticated:
        if request.method == 'GET':
            user = request.user.customer
            # print(f"get user customer {user}")
            serializer = CustomerSerializer(user, context={'request': request})
            serialized_data = serializer.data

            user_orders = Order.objects.filter(customer=user)
            # print(f"user orders {user_orders}")

            user_orders_serializer = OrderSerializer(user_orders, many=True, context={'request': request})

            user_orders_serialized_data = user_orders_serializer.data

            # print(f"user orders serializer {user_orders_serialized_data}")
            
            # Uncomment and use this block if needed in the future
            # current_year = datetime.datetime.now().year
            # year = request.GET.get('year')
            # try:
            #     year = int(year)
            # except (ValueError, TypeError):
            #     year = current_year
            # user_orders = Order.objects.filter(customer=user, complete=True)
            # user_order_serializer = OrderSerializer(user_orders, many=True,  context={'request': request})

            return Response({'customer': serialized_data, 'orders': user_orders_serialized_data})
        else:
            return Response({'message': 'Cannot retrieve user.'})
    else:
        return Response({'message': 'User not authenticated.'}, status=401)

@api_view(['GET'])
def get_users(request):
    if request.user.is_authenticated:
        try:
            customer = request.user.customer
        except ObjectDoesNotExist:
            return Response({"message": "Customer not found"}, status=status.HTTP_404_NOT_FOUND)
    else:
        device = request.COOKIES.get("my_cookie")
        try:
            customer = Customer.objects.get(device=device)
        except Customer.DoesNotExist:
            return Response({'message': 'Device customer not found'}, status=status.HTTP_404_NOT_FOUND)
    try:
        customers = Customer.objects.all()
    except Customer.DoesNotExist:
        return Response({'message': 'Customers not found'}, status=status.HTTP_404_NOT_FOUND)
    serializer = CustomerSerializer(customers, many=True)
    serialized_data = serializer.data

    return Response(serialized_data, status=status.HTTP_200_OK)

@api_view(['GET'])
def home(request):
    '''
    if request.user.is_authenticated:
        print(f"request user {request.user}")
        return JsonResponse({'message': 'No cookie needed.'})
    else:
    '''
    
    '''
    user = request.user.customer
    print(f"home request.user {user}")
    try: 
        customer = request.user.customer
        print(f"home customer {customer}")
    except:
        pass
    '''
    
    #print(f"request user {request.user.customer}")
    '''
    print("Is user authenticated?", request.user.is_authenticated)
    if hasattr(request.user, 'customer'):
        print(f"request user {request.user.customer}")
    else:
        print("User has no associated customer.")
    '''

    my_cookie_value = request.COOKIES.get('my_cookie')
    
    
    if my_cookie_value is None:
        my_uuid = uuid.uuid4()
        response = JsonResponse({'message': 'Hello from Django'})
        response['Access-Control-Allow-Origin'] = 'http://localhost:3000'

        if request.is_secure():

            response.set_cookie('my_cookie', my_uuid, secure=True, samesite='None')
        else:
            response.set_cookie('my_cookie', my_uuid, secure=True, samesite='None')

        return response
    
    #if my_cookie_value == 'deleted':
    #    response = JsonResponse({'message': 'Cookie deleted'})
    #    response['Access-Control-Allow-Origin'] = 'http://localhost:3000'
    #    response.set_cookie('my_cookie', 'cookie_value')

    #    return response
    
    return JsonResponse({'message':'Success'})

def cookie_monster(request):
    my_cookie_value = request.COOKIES.get('my_cookie')

    # if my_cookie_value:
    #     # print(f"my cookie {my_cookie_value}")
    # else:
    #     # print("Cookie 'my_cookie' does not exist")
    # return JsonResponse({'message':'Success'})

@api_view(['GET'])
def get_products(request):

    #if request.method == "GET":
    products = Product.objects.all()

    # serializing data, adding the context={"request": request} allows the full image url to post
    serializer = ProductSerializer(products, many=True, context={"request": request})
    serialized_data = serializer.data
    
    # return the serialized data as a response
    return Response(serialized_data)

@api_view(['GET', 'POST'])
#@csrf_exempt
def get_single_product(request, pk):
    if request.method == 'GET':
        product = Product.objects.get(id=pk)

        serializer = ProductSerializer(product, context={"request": request})
        serialized_data = serializer.data
        return Response(serialized_data)

    if request.method == 'POST':
        product = Product.objects.get(id=pk)

        '''
        if request.user.is_authenticated:
            customer = request.user.customer
            print(f"customer {customer}")
        else:
            device = request.COOKIES.get('my_cookie')
            print(f"my cookie {device}")
            customer, created = Customer.objects.get_or_create(device=device)
        
        '''
        # Get user account info
        try:
            customer = request.user.customer
        except:
            device = request.COOKIES.get('my_cookie')
            #print(f"single product my cookie {device}")
            customer, created = Customer.objects.get_or_create(device=device)
            
            '''
            if created:
                response = HttpResponse('New customer created')
                response.delete_cookie('my_cookie')
                return response
            else:
                return HttpResponse('Existing customer retrieved')
            '''
            
        # print(f"customer stripe id {customer.customer_stripe_id}")
        if customer.customer_stripe_id:
            print(f"Stripe customer id exists")
        else:
            # Create a Stripe customer for the anonymous user
            stripe_customer = stripe.Customer.create(
                # Provide a default or placeholder email
                email='anonymous@example.com',  
                # Store your own customer ID in metadata
                metadata={'customer_id': customer}  
            )

            customer.customer_stripe_id = stripe_customer.id
            customer.save()

        order, created = Order.objects.get_or_create(customer=customer, complete=False)
        # print(f"single product order {order}")
        
        order_items_in_order = order.orderitem_set.all()
        if order_items_in_order.exists():
            for item in order.orderitem_set.all():
                print()
                print("from order creation")
                print(f"order item id {item.id} order item quantity {item.quantity}")
                print()
                print()
        else:
            print(f"No order items in order.")

        orderItem, created = OrderItem.objects.get_or_create(order=order, product=product)
        # print(f"order item quantity on create {orderItem.quantity}")

        data = request.data
        #print(f"create order item data {data}")

        quantity = data['quantity']
        # print(f"quantity from frontend", quantity)

        #print(f"quantity {quantity}")

        orderItem.quantity += int(quantity)
        orderItem.save()

        # print(f"order item quantity after save {orderItem.quantity}")

        #product.quantity = product.quantity - int(quantity)
        #product.save()

        for after_saved_item in order.orderitem_set.all():
            print(f"After saved id {after_saved_item.id}")
            print()
            print(f"After saved quantity {after_saved_item.quantity}")

        
        
        '''
        cart = request.session.get('cart', {})
        cart[product.id] = {
            'product_id': product.id,
            'quantity': int(quantity),
            'price': product.price,
        }
        request.session['cart'] = cart
        '''

        return Response({'message': 'Order has been created.'})
    
    return Response({'message': 'Invalid request method'})

@api_view(['POST'])
def merge_guest_cart_with_user(request):
    user = request.user.customer
    data = request.data
    guest_cart_data = data['guest_cart_order_number']

    try:
        user_order = Order.objects.get(customer=user)
    except Order.DoesNotExist:
        user_order = None

    try:
        anon_order = Order.objects.get(id=guest_cart_data)

        if user_order:
            # Merge order items from the anonymous order into the users's order
            for anon_item in anon_order.orderitem_set.all():
                # Check if the item already exists in the user's order
                existing_item, created = OrderItem.objects.get_or_create(order=user_order, product=anon_item.product, quantity=anon_item.quantity)

                # print(f"anon item quantity", anon_item.quantity)
                
                if not created:
                    # If the item already exists, update its quantity or any other relevant fields
                    existing_item.quantity += anon_item.quantity
                    existing_item.save()
                
                # Delete the item from the anonymous order
                anon_item.delete()
            anon_order.delete()
        else:
            # Assign the anonymous order directly to the logged in user
            anon_order.customer = user
            anon_order.save()

        # Delete the anonymous order after merging or assigning
        #anon_order.delete()

        return Response({'message': 'Guest cart merged with user cart successfully.'}, status=status.HTTP_200_OK)
    except Order.DoesNotExist:
        return Response({'message': 'Guest cart not found.'}, status=status.HTTP_404_NOT_FOUND)


'''
@api_view(['POST'])
def merge_guest_cart_with_user(request):
    user = request.user.customer
    print(f"user {user}")
    data = request.data
    print(f"data {data}")
    guest_cart_data = data['guest_cart_order_number']

    try:
        anon_order = Order.objects.get(id=guest_cart_data)
        print(f"anon_order {anon_order}")
        anon_order.customer = user
        anon_order.save()
        return Response({'message': 'Guest cart merged with user cart successfully.'}, status=status.HTTP_200_OK)
    except Order.DoesNotExist:
        return Response({'message': 'Guest cart not found.'}, status=status.HTTP_404_NOT_FOUND)
'''

    #anon_order = Order.objects.get(id=guest_cart_data)
    #anon_order.customer = user
    #anon_order.save()
    #user = request.user
    #user_cart = user.customer.order_set.filter(complete=False).first()
    
'''
    if user_cart:
        for product_id, cart_item in guest_cart_data.items():
            product = Product.objects.get(id=product_id)
            quantity = cart_item['quantity']

            # Check if the same product is already in the user's cart
            existing_item = user_cart.orderitem_set.filter(product=product)

            if existing_item:
                existing_item.quantity += quantity
                existing_item.save()
            else:
                OrderItem.objects.create(order=user_cart, product=product, quantity=quantity)
    
    return Response({'message': 'Guest cart merged with user cart.'})
'''

'''
@api_view(['GET'])
def order(request):
    #print(f"order request cookies {request.COOKIES}")
    #print(f" user {request.user}")
    
    
    if request.user.is_authenticated:
        customer = request.user.customer
        print(f"customer {customer}")
    else:
        device = request.COOKIES.get('my_cookie')
        print(f"my cookie {device}")
        customer = Customer.objects.get(device=device)
    
    

    
    try:
        customer = request.user.customer
    except:
        device = request.COOKIES.get('my_cookie')
        #print(f"my cookie in order {device}")
        customer = Customer.objects.get(device=device)

    print(f"customer {customer}")
    

    order = Order.objects.get(customer=customer, complete=False)
    print(f"get order {order}")
    
    serializer = OrderSerializer(order)

    

    serialized_data = serializer.data
    #print(f"serialized data {serialized_data}")

    return Response(serialized_data, status=status.HTTP_200_OK)
"""else:
    return Response({'error': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)"""
'''

'''
@api_view(['GET'])
def order(request):
    if request.user.is_authenticated and not request.user.is_staff:
        try:
            customer = request.user.customer
        except ObjectDoesNotExist:
            return Response({'message': 'Request User Customer not found'}, status=status.HTTP_404_NOT_FOUND)
    else:
        device = request.COOKIES.get('my_cookie')
        try:
            customer = Customer.objects.get(device=device)
        except Customer.DoesNotExist:
            # Handle the case when the customer does not exist for both authenticated and anonymous users.
            # For example, you could create a new customer or redirect the user to a registration page.
            # You might want to add appropriate code here based on your application's logic.
            return Response({'message': 'Device Customer not found'}, status=status.HTTP_404_NOT_FOUND)
    #order = Order.objects.get(customer=customer, complete=False)
    
    
    try:
        order = Order.objects.get(customer=customer, complete=False)
        print(f"order {order} order in {order.customer}, order id {order.id}")
        for item in order.orderitem_set.all():
            print(f"order item id {item.id}")
            print(f"order item quantity {item.quantity}")
    except Order.DoesNotExist:
        # Handle the case when there is no matching order for the customer
        # For example, you could create a new order or display a message to the user.
        # You might want to add appropriate code here based on your application's logic.
        return Response({'message': 'Order not found'}, status=status.HTTP_404_NOT_FOUND)

    serializer = OrderSerializer(order)
    
    serialized_data = serializer.data
    print(f"order serializer {serialized_data}")

    return Response(serialized_data, status=status.HTTP_200_OK)
'''

@api_view(['GET'])
def order(request):
    if request.user.is_authenticated:
        try:
            customer = request.user.customer
        except ObjectDoesNotExist:
            return Response({'message': 'Customer not found'}, status=status.HTTP_404_NOT_FOUND)
    else:
        device = request.COOKIES.get('my_cookie')
        try:
            customer = Customer.objects.get(device=device)
        except Customer.DoesNotExist:
            return Response({'message': 'Device customer not found'}, status=status.HTTP_404_NOT_FOUND)
    try:
        order = Order.objects.get(customer=customer, complete=False)
    except Order.DoesNotExist:
        return Response({'message': 'Order not found'}, status=status.HTTP_404_NOT_FOUND)
    
    order_items_in_order = order.orderitem_set.all()

    if order_items_in_order.exists():
        # print(f"order from order view {order}")
        for item in order.orderitem_set.all():
            print(f"item id {item.id} item quantity {item.quantity}")
    else:
        print(f"No order items in Order from order function")

    serializer = OrderSerializer(order, context={"request": request})
    serialized_data = serializer.data

    # print(f"order {serialized_data}")

    return Response(serialized_data, status=status.HTTP_200_OK)


@api_view(['GET'])
def get_order_by_year(request):
    if request.method == 'GET':
        user = request.user.customer
        # print(f"order year user {user}")

        current_year = datetime.datetime.now().year

        year = request.GET.get('year')
        # print(f"year {year}")

        try:
            year = int(year)
        except (ValueError, TypeError):
            year = current_year

        user_year_orders = Order.objects.filter(customer=user, complete=True, date_ordered__year=year)

        if user_year_orders.exists():
            user_year_orders_serializer = OrderSerializer(user_year_orders, many=True, context={'request': request})
            return Response({'user_year_orders_serializer': user_year_orders_serializer.data}, status=status.HTTP_200_OK)
        else:
            return Response({'message': "No orders found for the specified year."}, status=status.HTTP_404_NOT_FOUND)
    else:
        return Response({'message': "Invalid request method."}, status=status.HTTP_400_BAD_REQUEST)

@api_view(['PATCH', 'delete'])
def update_order_item(request, pk):
    '''
    if request.user.is_authenticated:
        customer = request.user.customer
        print(f"customer {customer}")
    else:
        device = request.COOKIES.get('my_cookie')
        print(f"my cookie {device}")
        customer, created = Customer.objects.get_or_create(device=device)
    '''
        
    if request.user.is_authenticated:
        try:
            customer = request.user.customer
            # print(f"customer does exist {customer}")
        except ObjectDoesNotExist:
            return Response({'message': 'Customer not found'}, status=status.HTTP_404_NOT_FOUND)
    else:
        device = request.COOKIES.get('my_cookie')
        try:
            customer = Customer.objects.get(device=device)
        except Customer.DoesNotExist:
            # Handle the case when the customer does not exist for both authenticated and anonymous users.
            # For example, you could create a new customer or redirect the user to a registration page.
            # You might want to add appropriate code here based on your application's logic.
            return Response({'message': 'Customer not found'}, status=status.HTTP_404_NOT_FOUND)

    try:
        order = Order.objects.get(customer=customer, complete=False)
    except Order.DoesNotExist:
        # Handle the case when there is no matching order for the customer
        # For example, you could create a new order or display a message to the user.
        # You might want to add appropriate code here based on your application's logic.
        return Response({'message': 'Order not found'}, status=status.HTTP_404_NOT_FOUND)
    
    order_item = OrderItem.objects.get(id=pk)
    # print(f"order item product id {order_item.product.id}")

    if request.method == 'PATCH':
        
        # print(f"request {request.data}")
        data = request.data
        # print(f"data {data}")

        new_quantity = int(data['quantity'])
        #order_item.quantity = int(data['quantity'])

        #quantity_difference = new_quantity - order_item.quantity

        # Update product quantity
        # print(f"order item quantity before save {order_item.quantity}")
        
        """
        product = Product.objects.get(id=order_item.product.id)
        product.quantity = product.quantity + order_item.quantity - new_quantity
        product.save()
        """

        # Calculate difference in quantities
        if new_quantity <= 0:
            print(f"new quantity can't be less than or = to 0")
        elif new_quantity > order_item.product.quantity:
            print(f"new quantity can't be greater than product quantity")
        else:
            order_item.quantity = new_quantity
            order_item.save()

            print(f"order item quantity has been updated.")
        

        # print(f"order item {order_item}")

        serializer = OrderItemSerializer(order_item, context={"request": request})
        serialized_data = serializer.data
        return Response(serialized_data)
    
    '''
    if request.method == 'DELETE':
        order_item.delete()
        order_item.save()

        serializer = OrderItemSerializer(order_item)
        serialized_data = serializer.data
        return Response(serialized_data)
    '''

@api_view(['delete'])
def delete_order_item(request, pk):
    if request.user.is_authenticated:
        customer = request.user.customer
        # print(f"customer {customer}")
    else:
        device = request.COOKIES.get('my_cookie')
        # print(f"my cookie {device}")
        customer, created = Customer.objects.get_or_create(device=device)

    order = Order.objects.get(customer=customer.id, complete=False)
    # print(f"order {order}")
    order_item = OrderItem.objects.get(id=pk)
    # print(f"order item order {order_item.order.id}")

    product_id = order_item.product.id

    product = Product.objects.get(id=product_id)
    
    order_item_id = order_item.id



    
    if request.method == 'DELETE':
        #data = request.data
        #product.quantity = product.quantity + order_item.quantity
        #product.save()

        order_item.delete()
        #order_item.save()

        # print(f"order item id", order_item_id)
        if order.orderitem_set.count() == 0:
            order.delete()

        serializer = OrderItemSerializer(order_item)
        serialized_data = serializer.data
        return Response({'id': order_item_id, "message": "order item deleted"})
    
    # 4f7a189e-17d2-4ff8-94a8-9e87d86578ff
    # hb63tt5ocd6qryb6f019rbslx25smfs1

@api_view(['POST'])
def submit_order_and_stripe_payment(request):
    if request.method == 'POST':
        if request.user.is_authenticated:
            customer = request.user.customer
        else:
            device = request.COOKIES.get('my_cookie')
            customer, created = Customer.objects.get_or_create(device=device)

        order = Order.objects.get(customer=customer.id, complete=False)
        # print(f"Order {order}")

        order_items = OrderItem.objects.filter(order=order)

        unavailable_products = []
        any_item_out_of_stock = False

        for item in order_items:
            if item.product.quantity <= 0:
                unavailable_products.append(item.product.name)
                any_item_out_of_stock = True
                

        if any_item_out_of_stock:
            return Response({"error": f"The following products are out of stock: {', '.join(unavailable_products)}. Please remove the items from cart or wait until item's stock has been updated. "}, status=status.HTTP_400_BAD_REQUEST)
        else:
            for item in order_items:
                item.product.quantity -= item.quantity
                item.product.sold += item.quantity
                item.product.save()

        '''
        Monkey id: 148, email: monkey@gmail.com
        '''

        #address = Address.objects.get(customer=customer, complete=False)

        data = request.data
        # print(f"order data", data)
        payment_method_id = data['payment_method_id']
        address_type = data['address_type']
        first_name = data['first_name']
        last_name = data['last_name']
        email = data['email']
        # print(f"email {email}")
        street_address = data['street_address']
        apt = data['apt']
        city = data['city']
        state = data['state']
        zipcode = data['zipcode']
        is_checked = data['is_checked']
        total_with_tax = data['total_with_tax']
        # print(f"is_checked {is_checked}")
        # print(f"total_with_tax {total_with_tax}")

        update_anon_customer_email_on_purchase = stripe.Customer.modify(
            customer.customer_stripe_id,
            email=email,
        )

        # print(f"updated customer email {update_anon_customer_email_on_purchase}")

        stripe_payment_intent = stripe.PaymentIntent.create(
            customer=customer.customer_stripe_id,
            payment_method=payment_method_id,
            currency='usd',
            amount=int(order.get_cart_total * 100),
            automatic_payment_methods={
                'enabled': True,
                'allow_redirects': 'never',
            },
            confirm=True
        )

        # print(f"stripe payment intent {stripe_payment_intent}")

        # address_type = request.data.get('address_type')
        address_type_id = request.data.get('id')
        # print(f"address type {address_type}")
        # print(f"address type id {address_type_id}")
        

        if address_type_id == 0:
            shipping_address = Address(
                customer=customer,
                is_active=True,
                address_type=address_type,
                first_name = first_name,
                last_name = last_name,
                street_address = street_address,
                apt = apt,
                city = city,
                state = state,
                zipcode = zipcode
            )
            shipping_address.save()
        else:
            shipping_address = Address.objects.get(id=address_type_id)

        

        order.stripe_charge_id = stripe_payment_intent.latest_charge
        order.first_name = first_name
        order.last_name = last_name
        order.user_email = email
        order.shipping_address = shipping_address
        order.complete=True
        #order.shipping_address = f"{street_address}, Apt {apt}, {city}, {state}, {zipcode}"
        if is_checked:
            order.billing_address = order.shipping_address
        order.save()

        # print(f"order complete {order.complete}")

        serializer = OrderSerializer(order, context={"request": request})
        
        # send an email confirmation
        subject = 'Order Confirmation'
        from_email = 'ecommercestore8823@gmail.com'
        recipient_list = [email]
        
        # customize context for order_confirmation_email.html
        context = {
            'order_number': order.id,
            'order_status': 'completed',
        }

        # render the email template with dynamic data
        message = render_to_string('core/order_confirmation_email.html', context)

        # send the email
        send_mail(subject, '', from_email, recipient_list, html_message=message)

    return Response({'message': 'Order has been placed.', 'order': serializer.data})

        # 8086bd96-a87c-4fdf-b74b-b602e9b9303b

@api_view(['POST'])
def create_billing_address(request):
    if request.method == 'POST':
        if request.user.is_authenticated:
            customer = request.user.customer
        else:
            device = request.COOKIES.get('my_cookie')
            # print(f"device {device}")

            customer, created = Customer.objects.get_or_create(device=device)
            # print(f"customer device {customer}")

        # print(f"customer {customer}")

        order = Order.objects.get(customer=customer.id, complete=False)
        # print(f"order shipping address {order.shipping_address}")

        data = request.data
        # print(f"billing data {request.data}")

        
        address_type = request.data.get('address_type')
        address_id = request.data.get('id')
        # print(f"billing address id {address_id}")

    

        # Create an AddressSerializer instance and specify the context with the address_type
        #serializer = AddressSerializer(data=request.data, context={'address_type': address_type})
        
        
        serializer = AddressSerializer(data=request.data)

        #print(f"billing address {serializer}")

        if serializer.is_valid():
            
            if address_id == "":


            
                billing_address = Address(
                    customer=customer,
                    is_active=True,
                    address_type=address_type,
                    first_name = serializer.validated_data.get('first_name'),
                    last_name = serializer.validated_data.get('last_name'),
                    street_address = serializer.validated_data.get('street_address'),
                    apt = serializer.validated_data.get('apt'),
                    city=serializer.validated_data.get('city'),
                    state=serializer.validated_data.get('state'),
                    zipcode=serializer.validated_data.get('zipcode')
                )
                billing_address.save()

                
            else:
                billing_address = Address.objects.get(id=address_id)

            if address_type == 'billing':
                order.billing_address = billing_address
            elif address_type == 'shipping':
                order.shipping_address = billing_address

            order.save()
            
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        

@api_view(['PATCH'])
def edit_shipping_billing_address(request):
    if request.user.is_authenticated:
        user = request.user.customer
        data = request.data

        try:
            address_data = data
            # print(f"edit address data", data)
            address_id = data['id']
            first_name = data['first_name']
            # print(f"edit first name address", first_name)
            address = Address.objects.get(id=address_id)

            address_serializer = AddressSerializer(instance=address, data=data, partial=True)

            if address_serializer.is_valid():
                address_serializer.save()
                return Response(address_serializer.data, status=status.HTTP_200_OK)
            else:
                return Response(address_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Address.DoesNotExist:
            return Response({'error': 'Address not found'}, status=status.HTTP_404_NOT_FOUND)
        except KeyError:
            return Response({'error': 'Address ID is required'}, status=status.HTTP_400_BAD_REQUEST)
    return Response({'error': 'User not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

        

        
        

@api_view(['GET'])
def get_billing_shipping_address(request):
    if request.user.is_authenticated:
        user = request.user.customer
        
        user_shipping_address = Address.objects.filter(customer=user, address_type='shipping', is_active=True).first()
        user_billing_address = Address.objects.filter(customer=user, address_type='billing', is_active=True).first()

        shipping_address_data = AddressSerializer(user_shipping_address).data if user_shipping_address else None
        billing_address_data = AddressSerializer(user_billing_address).data if user_billing_address else None

        return Response({
            'shipping_address': shipping_address_data,
            'billing_address': billing_address_data
        }, status=status.HTTP_200_OK)
    else:
        return Response({'message': 'User is not authenticated.'}, status=status.HTTP_401_UNAUTHORIZED)


@api_view(['GET'])
def search_for_submitted_order(request):
    if request.method == 'GET':
        email = request.query_params.get('email')
        order_number = request.query_params.get('orderNumber')

        try:
            order = Order.objects.get(id=order_number, user_email=email, complete=True)
            # print(f"order items {order.orderitem_set.all()}")
            
            if order:
                
                serializer = OrderSerializer(order, context={"request": request})
                serializer_data = serializer.data

                return Response(serializer_data, status=status.HTTP_200_OK)
            else:
                return Response({'message': 'Order does not exist'}, status=status.HTTP_404_NOT_FOUND)
        except Order.DoesNotExist:
            return Response({'message': 'Order does not exist'}, status=status.HTTP_404_NOT_FOUND)
        
def return_whole_order(request):
    if request.method == 'GET':
        order_id = request.query_params.get('order-id')

        try:
            order = Order.objects.get(id=order_id)

            if order:
                serializer = OrderSerializer(order)
                serializer_data = serializer.data

                return Response(serializer_data, status=status.HTTP_200_OK)
            else:
                return Response({'message': 'Order does not exist'}, status=status.HTTP_404_NOT_FOUND)
        except Order.DoesNotExist:
            return Response({'message': 'Order does not exist'}, status=status.HTTP_404_NOT_FOUND)

@api_view(['GET', 'PATCH'])
def return_single_order_item(request, pk):
    
    try:
        order = Order.objects.get(id=pk)
    except Order.DoesNotExist:
        return Response({"error": "Order not found"}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'GET':

        
        serializer = OrderSerializer(order, context={"request": request})
        serialized_data = serializer.data

        return Response(serialized_data, status=status.HTTP_200_OK)

    
    if request.method == 'PATCH':
        item_updates = request.data.get('order_items', []) # Get the list of item updates from the request data
        # print(f"item updates {item_updates}")
        updated_items = []

        #data_from_frontend = item_updates['order_items']
        #print(f"data_from_frontend {data_from_frontend}")

        for item_update in item_updates:
            item_id = item_update.get('order_item_id')
            quantity_returned = int(item_update.get('item_amount_returning', 0)) # Default to 0 if not provided

            try:
                order_item = OrderItem.objects.get(id=item_id)
                # print("order item product detail image", order_item.product.image)

                if quantity_returned > order_item.quantity:
                    print(f"{quantity_returned} is greater than {order_item.quantity}")
                    return Response({'message': 'Quantity returned exceeds available quantity.'}, status=status.HTTP_400_BAD_REQUEST)

                order_item.item_amount_returning += quantity_returned
                order_item.item_process_return_initiated = True

                if order_item.item_amount_returning == order_item.quantity:
                    order_item.all_items_returned = True
                    order_item.partial_returned = False
                else:
                    order_item.partial_returned = True

                order_item.save()

                # serialize the updated OrderItem and add it to the list
                """
                    The instance and context is to show full url of image (http)
                """
                updated_item_serializer = OrderItemSerializer(instance=order_item, context={'request': request})
                updated_items.append(updated_item_serializer.data)

            except OrderItem.DoesNotExist:
                return Response({'message': 'Order item does not exist'}, status=status.HTTP_404_NOT_FOUND)
        # print(f"updated items {updated_items}")
        return Response({'message': 'Items returned successfully.', 'updated_items': updated_items}, status=status.HTTP_200_OK)
        



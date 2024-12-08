from django.urls import path
from . import views

from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView,
)

urlpatterns = [
    #path('login', views.LoginView.as_view(), name='login'),
    path('register', views.register_user, name='register'),
    path('token', views.MyTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('refresh', TokenRefreshView.as_view(), name='token_refresh'),
    path('verify', TokenVerifyView.as_view(), name='verify'),
    path('', views.home, name='home'),
    path('password-reset', views.password_reset_view, name='password-reset'),
    path('password-reset-confirm', views.password_reset_confirm_view, name='password-reset-confirm'),
    path('get-cookie', views.cookie_monster, name='get-cookie'),
    path('logout-user', views.logout_view, name='logout-user'),
    path('user', views.get_user, name='user'),
    path('users', views.get_users, name='users'),
    path('products', views.get_products, name='products'),
    path('product/<str:pk>', views.get_single_product, name='product'),
    path('merge', views.merge_guest_cart_with_user, name='merge'),
    path ('order', views.order, name='order'),
    path ('order-year', views.get_order_by_year, name='order-year'),
    path('create-billing-address', views.create_billing_address, name='create-billing-address'),
    path('billing-shipping-address', views.get_billing_shipping_address, name='billing-shipping-address'),
    path('edit-shipping-billing', views.edit_shipping_billing_address, name='edit-billing-shipping'),
    path('update-order-item/<str:pk>', views.update_order_item, name='update-order-item'),
    path('delete-order-item/<str:pk>', views.delete_order_item, name='delete-order-item'),
    path('submit-order', views.submit_order_and_stripe_payment, name="submit-order"),
    path('search-order', views.search_for_submitted_order, name="search-order"),
    path('return-partial-order/<str:pk>', views.return_single_order_item, name='return-partial-order')
]


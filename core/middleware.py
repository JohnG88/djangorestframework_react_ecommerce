from django.http import HttpResponse
from django.utils.deprecation import MiddlewareMixin
from django.core.exceptions import ObjectDoesNotExist
import uuid


class MyCookieMiddleware(MiddlewareMixin):
    def process_request(self, request):
        my_cookie_value = request.COOKIES.get("my_cookie")

        if my_cookie_value is None:
            # Generate a new UUID if 'my_cookie' is not present
            my_uuid = str(uuid.uuid4())
            request.my_cookie = my_uuid

    def process_response(self, request, response):
        # Set the 'my_cookie' for all users (authenticated and anonymous)
        if hasattr(request, 'my_cookie'):
            response.set_cookie('my_cookie', request.my_cookie, secure=True, samesite='None', path='/')
        return response



"""--- OG Function ---"""
# class MyCookieMiddleware(MiddlewareMixin):
#     def process_request(self, request):
#         my_cookie_value = request.COOKIES.get("my_cookie")

#         if my_cookie_value is None:
#             # If 'my_cookie' is not present in the request, generate a new UUID
#             my_uuid = str(uuid.uuid4())
#             # Set a new cookie on the response
#             response = HttpResponse()
#             response.set_cookie('my_cookie', my_uuid)
#             return response


#     def process_response(self, request, response):
#         # Perform any processing needed before sending the response
#         return response

# class MyCookieProcessingMiddleware:
#     def process_request(self, request):
#         # Will only add cookie if request does not have it already
#         if not request.COOKIES.get('your_desired_cookie'):
#             request.COOKIES['set_your_desired_cookie'] = 'value_for_desired_cookie'

#     def process_response(self, request, response):
#         # Your desired cookie will be available in every HttpResponse parser like a browser, but not in Django views
#         if not request.COOKIES.get('your_desired_cookie'):
#             response.set_cookie('set_your_desired_cookie', 'value_for_desired_cookie')

#         return response
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model

class EmailBackend(ModelBackend):
    def authenticate(self, request, email=None, password=None, **kwargs):
        UserModel = get_user_model()

        try:
            # Try to find the user based on the email address
            user = UserModel.objects.get(email=email)
        except UserModel.DoesNotExist:
            return None

        # If the password is valid and the user can authenticate
        if user.check_password(password) and self.user_can_authenticate(user):
            return user
        return None
from django.contrib.auth.backends import BaseBackend
from .models import CustomUser
from django.contrib.auth.hashers import check_password
class CustomUserBackend(BaseBackend):
    def authenticate(self,request,username=None, password=None):
        try:
            user = CustomUser.objects.get(username=username)
            if user.check_password(password):
                return user
        except CustomUser.DoesNotExist:
            pass
        return None
    def get_user(self,user_id):
        try :
            CustomUser.objects.get(pk=user_id)
        except CustomUser.DoesNotExist:
            return None
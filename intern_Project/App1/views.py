from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.views import APIView
from rest_framework.response import Response
from django.http import JsonResponse
from django.conf import settings  # Import Django settings module
from .models import  *
from .serializers import *
from django.shortcuts import render
from rest_framework import generics,status,viewsets
from rest_framework.views import APIView
from django.contrib.auth.hashers import make_password,check_password
from rest_framework.permissions import AllowAny


# # CRUD Operations  user role 
class UserRoleListCreateView(generics.ListCreateAPIView):
     queryset = UserRole.objects.all()
     serializer_class =UserRoleSerializer

# class UserRoleDetailView(generics.RetrieveUpdateDestroyAPIView):
#     queryset = UserRole.objects.all()
#     serializer_class = UserRoleSerializer
#     def destroy(self,request,*args,**kwargs):
#         instance = self.get_object()
#         instance.is_active = False
#         instance.is_archived = True
#         instance.save()
#         return Response({'message':"User-Role deactivated successfuly"},status=status.HTTP_204_NO_CONTENT)
    
#     def patch(self,request,*args,**kwargs):
#         instance = self.get_object()
#         instance.is_active =True
#         instance.is_archived= False
#         instance.save()
#         serializer = self.get_serializer(instance)
#         return Response(serializer.data)






class UserRoleDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = UserRole.objects.all()
    serializer_class = UserRoleSerializer
    def destroy(self,request,*args,**kwargs):
        instance = self.get_object()
        instance.is_active = False
        instance.save()
        ArchivedUserRole.objects.create(
            archived_role_name = instance.role_name
        )
        return Response({'message':'User-role Deactivated '},status=status.HTTP_200_OK)
    
    def patch(self,request,*args,**kwargs):
        instance = self.get_object()
        instance.is_active =True
        instance.save()
        return Response({'message':'User role Reactivated successfully'},status=status.HTTP_200_OK)

#CRUD Operations for User
class UserListCreateView(generics.ListCreateAPIView):
     queryset = CustomUser.objects.all()
     serializer_class=UserSerializer

class UserDetailView(generics.RetrieveUpdateDestroyAPIView):
     queryset =CustomUser.objects.all()
     serializer_class=UserSerializer
     def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.status = 'Archived'
        instance.save()
        return Response({'message': 'User archived successfully'}, status=status.HTTP_204_NO_CONTENT)

class UserActivateApi(generics.UpdateAPIView):
    queryset = CustomUser.objects.filter(status='Archived')
    serializer_class = UserSerializer

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.status = 'Active'
        instance.save()
        return Response({'message': 'User  activated successfully'}, status=status.HTTP_200_OK)

    #  def destroy(self,request,*args,**kwargs):
    #     instance = self.get_object()
    #     instance.is_active = False
    #     instance.is_archived = True
    #     instance.save()
    #     return Response({'message':'User Deactivated and archived successfully'},status=status.HTTP_200_OK)
    #  def patch(self,request,*args,**kwargs):
    #      instance = self.get_object()
    #      instance.is_active =True
    #      instance.is_archived =False
    #      instance.save()
    #      serializer =  self.get_serializer(instance)
    #      return Response(serializer.data)



# Login for the users along with authentication
import secrets
import jwt
import datetime
# class LoginView(APIView):

#     permission_classes = [AllowAny]

#     def post(self, request):
#         username = request.data.get('username')
#         password = request.data.get('password')

#         try:
#             user = CustomUser.objects.get(username=username)
#         except CustomUser.DoesNotExist:
#             return Response({'message': 'Invalid username'}, status=status.HTTP_401_UNAUTHORIZED)

#         if not check_password(password, user.password):
#             return Response({'message': 'Invalid password'}, status=status.HTTP_401_UNAUTHORIZED)

#         serializer = UserSerializer(user)

#         # Check if the access token already exists for the user
#         access_token_obj, created = AccessToken.objects.get_or_create(user=user)

        
#         if created or not access_token_obj.token:
#             access_token_obj.token = secrets.token_hex(40)  
#             access_token_obj.save()

#         return Response({
#             'user': serializer.data,
#             'access_token': access_token_obj.token
#         }, status=status.HTTP_200_OK)






from rest_framework_simplejwt.tokens import RefreshToken
class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        try:
            user = CustomUser.objects.get(username=username)
        except CustomUser.DoesNotExist:
            # return Response({'message': 'Invalid username'}, status=status.HTTP_401_UNAUTHORIZED)
            user = None

        if user and  check_password(password, user.password):
            refresh = RefreshToken.for_user(user)
            # return Response({'message': 'Invalid password'}, status=status.HTTP_401_UNAUTHORIZED)

        serializer = UserSerializer(user)

        # Check if the permanent access token already exists for the user
        access_token_obj, created = AccessToken.objects.get_or_create(user=user)
        access_token_obj.access_token = str(refresh.access_token)
        access_token_obj.save()
        # Return a response in all cases
        return Response({
            'user': serializer.data,
            'permanent_access_token': str(refresh.access_token)
         }, status=status.HTTP_200_OK)

from django.core.mail import send_mail
from django.urls import reverse
# class ForgotPasswordView(APIView):
#     def post(self, request):
#         username_or_email = request.data.get('username_or_email')

#         # Check if the user exists with provided username or email (case-insensitive)
#         users = CustomUser.objects.filter(email__iexact=username_or_email) | CustomUser.objects.filter(username__iexact=username_or_email)
#         user = users.first()

#         if not user:
#             return Response({'message': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

#         reset_token = secrets.token_urlsafe(40)
#         password_reset_token = PasswordResetToken.objects.create(user=user, token=reset_token)

#         # Send the password reset link via email
#         # reset_link = f'http://localhost:8000/App1/resetpassword?token={reset_token}'
#         # reset_link = request.build_absolute_uri(reverse("reset-password"))

#         send_mail(
#             'Password Reset',
#             f'Your Password reset token is : {reset_token}',
#             'from@example.com',
#             [user.email],
#             fail_silently=False,
#         )

#         return Response({'message': 'Password reset link sent successfully'}, status=status.HTTP_200_OK)

# class ResetPasswordView(APIView):
    # def post(self, request):
    #     token = request.data.get('token')
        
    #     new_password = request.data.get('new_password')

    #     # Step 2: Verify the received token's validity
    #     password_reset_token = PasswordResetToken.objects.filter(token=token).first()
    #     if not password_reset_token:
    #         return Response({'message': 'Invalid or expired token'}, status=status.HTTP_400_BAD_REQUEST)

    #     # Step 2: Reset the user's password securely
    #     user = password_reset_token.user
    #     user.password = make_password(new_password)
    #     user.save()

    #     # Step 2: Delete the used token after successful password reset
    #     password_reset_token.delete()

    #     return Response({'message': 'Password reset successful'}, status=status.HTTP_200_OK)
import random
class ForgotPasswordView(APIView):
    def post(self,request):
        username_or_email = request.data.get('username_or_email')
        users = CustomUser.objects.filter(email__iexact=username_or_email) | CustomUser.objects.filter(username__iexact=username_or_email)
        # user = users.first()
        if not users.exists():
            return Response({'message':'User not found'},status=status.HTTP_404_NOT_FOUND)
        
        otp = ''.join([str(random.randint(0,9)) for _ in range(6)])
        for user in users:
            password_reset_token , created = PasswordResetToken.objects.get_or_create(user=user)
            password_reset_token.otp=otp
            password_reset_token.save()
            send_mail (
                'Password Reset OTP',
                f'Your OTP for Password Reset is :{otp}',
                'from@example.com',
                [user.email],
                fail_silently=False,

            )
        return Response({'message':'Password reset OTP sent successfully'},status=status.HTTP_200_OK)
    
class ResetPasswordView(APIView):
    def post(self,request):
        otp = request.data.get('otp')
        new_password = request.data.get('new_password')
        confirm_password = request.data.get('confirm_password')
        
        if new_password != confirm_password:
            return Response({'message':'New Password and Confirm Password do not match '},status=status.HTTP_400_BAD_REQUEST)
        
        try:
            password_reset_token = PasswordResetToken.objects.get(otp=otp)
        except PasswordResetToken.DoesNotExist:
            return Response({'message':'Invalid or expired OTP'},status=status.HTTP_400_BAD_REQUEST)
        
        user = password_reset_token.user
        user.password = make_password(new_password)
        user.save()
        
        password_reset_token.delete()
        
        return Response({'message':'Password reset successfully'},status=status.HTTP_200_OK)


from rest_framework.permissions import IsAuthenticated,IsAdminUser
from .utils import is_super_admin
class PermissionView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self,request):
        if is_super_admin(request.user) or is_admin(request.user):
            permissions = Permission.objects.all()
            serializer = PermissionSerializer(permissions,many =True)
            return Response(serializer.data)
        return Response({'message':'Permission Denied.aAdmin access required.'}, status=status.HTTP_403_FORBIDDEN)
    
    def post(self,request):
        serializer = PermissionSerializer(data = request.data)
        if serializers.is_valid():
            if request.user.is_superuser:
                serializer.save()
                return Response({'message':'Permission created '}, status=status.HTTP_200_OK)
            else:
                return Response({'message':'Permission denied.Only super-admin can have all the permissions '}, status=status.HTTP_403_FORBIDDEN)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
 
class TimeCycleView(APIView):
    permission_classes=[AllowAny]
    def get_object(self, time_cycle_id=None):
        if time_cycle_id is not None:
            try:
                return TimeCycle.objects.get(pk=time_cycle_id)
            except TimeCycle.DoesNotExist:
                return None
        else:
            return TimeCycle.objects.all()

    def get(self, request, time_cycle_id=None):
        if time_cycle_id is not None:
            time_cycle = self.get_object(time_cycle_id)
            if time_cycle:
                serializer = TimeCycleSerializer(time_cycle)
                data = serializer.data
                data['days'] = time_cycle.get_days()
                return Response(data)
            else:
                return Response({'detail': 'Time-cycle not found'}, status=status.HTTP_404_NOT_FOUND)
        else:
            time_cycles = self.get_object()
            serializer = TimeCycleSerializer(time_cycles, many=True)
            data = serializer.data
            for time_cycle_data in data:
                time_cycle_instance = self.get_object(time_cycle_data['id'])
                if time_cycle_instance:
                    time_cycle_data['days'] = time_cycle_instance.get_days()
                else:
                    time_cycle_data['days'] = []
            return Response(data)

    def post(self, request):
        serializer = TimeCycleSerializer(data=request.data)
        if serializer.is_valid():
            time_cycle_instance = serializer.save()

            # Add days to TimeCycleDay model (excluding weekends)
            for day in time_cycle_instance.get_days():
                 TimeCycleDay.objects.create(time_cycle=time_cycle_instance, day=day)

            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, time_cycle_id):
        time_cycle = self.get_object(time_cycle_id)
        if time_cycle:
            serializer = TimeCycleSerializer(time_cycle, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({'detail': 'Time-cycle not found'}, status=status.HTTP_404_NOT_FOUND)

    def delete(self, request, time_cycle_id):
        time_cycle = self.get_object(time_cycle_id)
        if time_cycle:
            time_cycle.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        else:
            return Response({'detail': 'Time-cycle not found'}, status=status.HTTP_404_NOT_FOUND)           
            


class EmployeeCreateViewApi(generics.ListCreateAPIView):
    queryset = Employee.objects.all()
    serializer_class = EmployeeSerializer

class EmployeeDetailAPI(generics.RetrieveUpdateDestroyAPIView):
    queryset = Employee.objects.all()
    serializer_class = EmployeeSerializer
    
    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.status = 'Archived'
        instance.save()
        return Response({'message': 'Employee archived successfully'}, status=status.HTTP_204_NO_CONTENT)


class EmployeeActivateAPI(generics.UpdateAPIView):
    queryset = Employee.objects.filter(status='Archived')
    serializer_class = EmployeeSerializer

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.status = 'Active'
        instance.save()
        return Response({'message': 'Employee activated successfully'}, status=status.HTTP_200_OK)


class PermissionViewCreate(generics.ListCreateAPIView):
    queryset = Permission.objects.all()
    serializer_class = PermissionSerializer

class PermissionDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Permission.objects.all()
    serializer_class = PermissionSerializer

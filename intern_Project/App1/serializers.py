from rest_framework import serializers
from .models import *
from django.contrib.auth.hashers import make_password

class SuperadminSerializer(serializers.ModelSerializer):
    def create(self, validated_data):
        validated_data['password'] = make_password(validated_data.get('password'))
        return super().create(validated_data)
    class Meta:
        model = SuperAdmin  # Add this line to specify the model
        fields = ['id', 'superadmin_name', 'email', 'password']

class UserRoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserRole
        fields = '__all__'

class ArchivedUserRoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = ArchivedUserRole
        fields ='__all__'

        
class UserSerializer(serializers.ModelSerializer):
    user_role_name = serializers.SerializerMethodField()
    class Meta:
        model = CustomUser
        fields = ('id', 'username', 'email', 'password', 'user_role','status','user_role_name')
        extra_kwargs = {
            'password': {'write_only': True},
            'user_role': {'required': True}
        }
    def get_user_role_name(self,obj):
        return obj.user_role.role_name if obj.user_role else None
    def create(self, validated_data):
        validated_data['password'] = make_password(validated_data.get('password'))
        return super().create(validated_data)


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=100)
    password = serializers.CharField(max_length = 255,write_only = True)


# class ForgotPasswordSerializer(serializers.ModelSerializer):
#     username_or_email =  serializers.CharField()

# class PasswordResetTokenSerializer(serializers.ModelSerializer):
#     class Meta:
#         models = PasswordResetToken
#         fields = '__all__'

from datetime import timedelta

class PermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Permission
        fields = ['id', 'permission_name', 'user_role', 'allowed']

class EmployeeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Employee
        fields = ['id', 'employee_name', 'contact_no', 'email', 'address', 'designation', 'status']

class TimeCycleSerializer(serializers.ModelSerializer):
    class Meta:
        model = TimeCycle
        fields = ['id', 'time_cycle_name', 'start_date', 'end_date']
        def get_days(self, obj):
            return obj.get_days()

# class AllocationSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = Allocation
#         fields = ['id', 'allocation_name', 'time_cycle', 'employee', 'start_date', 'end_date', 'allocation_status']


# class UserLoginSerializer(serializers.Serializer):
    
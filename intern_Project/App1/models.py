from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.db.models.query import QuerySet


class SuperAdmin(models.Model):
    superadmin_name = models.CharField(max_length=255)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=255)

class UserRole(models.Model):
    role_name = models.CharField(max_length=50)

class ArchivedUserRole(models.Model):
    archived_role_name = models.CharField(max_length=100)
    def __str__(self):
        return self.archived_role_name


class CustomUser(models.Model):
    STATUS_CHOICES = [
        ('Active', 'Active'),
        ('Inactive', 'Inactive')
    ]
    username = models.CharField(max_length=100)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=100)  # Should be hashed and stored securely
    user_role = models.ForeignKey(UserRole, on_delete=models.CASCADE)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='Active') 
    
    def __str__(self):
        return self.username

class AccessToken(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE)
    token = models.CharField(max_length=100)

    def __str__(self):
        return f"Token for {self.user.username}"
    
    
class Permission(models.Model):
    permission_name = models.CharField(max_length=50)
    user_role = models.ForeignKey(UserRole, on_delete=models.CASCADE)
    allowed = models.BooleanField(default=False)




class Employee(models.Model):
    STATUS_CHOICES = [
        ('Active', 'Active'),
        ('Inactive', 'Inactive')
    ]
    
    employee_name = models.CharField(max_length=100)
    contact_no = models.CharField(max_length=20)
    email = models.EmailField(unique=True)
    address = models.TextField()
    designation = models.CharField(max_length=100)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='Active')

from datetime import timedelta
class TimeCycle(models.Model):
    time_cycle_name = models.CharField(max_length=100)
    start_date = models.DateField()
    end_date = models.DateField()
    def __str__(self):
        return self.time_cycle_name
    def get_days(self):
        days = [
            (self.start_date + timedelta(days=x)).strftime('%Y-%m-%d')
            for x in range((self.end_date - self.start_date).days + 1)
            if (self.start_date + timedelta(days=x)).weekday() not in [5, 6]  # Exclude Saturday (5) and Sunday (6)
        ]
        return days
class TimeCycleDay(models.Model):
    time_cycle = models.ForeignKey(TimeCycle, on_delete=models.CASCADE)
    day = models.DateField()

class Allocation(models.Model):
    STATUS_CHOICES = [
        (False, 'False'),
        (True, 'True')
    ]
    
    allocation_name = models.CharField(max_length=100)
    time_cycle = models.ForeignKey(TimeCycle, on_delete=models.CASCADE)
    employee = models.ForeignKey(Employee, on_delete=models.CASCADE)
    start_date = models.DateField()
    end_date = models.DateField()
    allocation_status = models.BooleanField(choices=STATUS_CHOICES, default=False)



from django.contrib.auth import get_user_model
from django.utils import timezone
import secrets
User = get_user_model()
from django.contrib.auth.tokens import default_token_generator

class PasswordResetToken(models.Model):
    user  = models.OneToOneField(CustomUser, on_delete=models.CASCADE)
    otp = models.CharField(max_length=255,unique=True)
    def generate_token(self):
        return default_token_generator.make_token(self.user)
    
    def __str__(self):
        return f"Reset token for {self.user.username}"
    # def save(self,*args,**kwargs):
    #     existing_token = PasswordResetToken.objects.filter(user =self.user).first()
    #     if existing_token:
    #         existing_token.otp=self.otp
    #         existing_token.save()
    #     else:
    #         super().save(*args,**kwargs)
    # def __str__(self):
    #     return f"Reset token for {self.user.username}"

    
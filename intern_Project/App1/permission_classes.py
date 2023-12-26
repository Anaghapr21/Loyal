from rest_framework import permissions
from rest_framework import generics
from .models import *
from .serializers import *


class SuperAdminPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.user_role == 'Super-Admin'
class PermissionListCreateView(generics.ListCreateAPIView):
    queryset = Permission.objects.all()
    serializer_class = PermissionSerializer
    permission_classes =[SuperAdminPermission]
class PermissionDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Permission.objects.all()
    serializer_class= PermissionSerializer
    permission_classes =[SuperAdminPermission]


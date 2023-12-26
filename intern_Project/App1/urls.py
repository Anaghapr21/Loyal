from django.urls import path,include
from App1.views import *
from rest_framework_simplejwt import views as jwt_views
urlpatterns =[
    path('user-roles/', UserRoleListCreateView.as_view(), name='user-list'),
    path('user-roles/<int:pk>/', UserRoleDetailView.as_view(), name='user-detail'),
    path('user/',UserListCreateView.as_view(),name='user'),
    path('user/<int:pk>/',UserDetailView.as_view(),name='user-detail'),
    path('user/<int:pk>/activate/',UserActivateApi.as_view(),name='User-Activate'),
    path('login/',LoginView.as_view(),name='login'),
    path('employee/',EmployeeCreateViewApi.as_view(),name='create-employee-api'),
    path('employee/<int:pk>/',EmployeeDetailAPI.as_view(), name='employee-details'),
    path('employee/<int:pk>/activate/',EmployeeActivateAPI.as_view(),name='status-active'),

    path('forgot-password/',ForgotPasswordView.as_view(), name='forgot-password'),
    path('resetpassword/', ResetPasswordView.as_view(), name='reset-password'),
    # path('verify-password/',VerifyPasswordView.as_view(),name='verify-password'),
    # path('update-password/',UpdatePasswordView.as_view(),name='update-password'),
    # path('resetpassword/<str:token>/', ResetPasswordView.as_view(), name='reset-password'),
    path('permission/',PermissionView.as_view(),name='permission'),
    # path('time-cycle/<int:time_cycle_id>/',TimeCycleView.as_view(),name='time-cycle')
    path('jwt/token/',jwt_views.TokenObtainPairView.as_view(),name='created-token'),
    path('jwt/refresh/',jwt_views.TokenRefreshView.as_view(),name='refresh-token'),
    path('timecycle/', TimeCycleView.as_view(), name='time_cycle_list'),  
    path('timecycle/<int:time_cycle_id>/', TimeCycleView.as_view(), name='time_cycle_detail'),
    path('permission/',PermissionViewCreate.as_view(),name='permission-create'),
    path('permission/<int:pk>/',PermissionDetailView.as_view(),name='permission-detail')
    
   
]
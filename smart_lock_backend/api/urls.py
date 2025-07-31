from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    health,
    UserRegisterView,
    UserLoginView,
    UserInfoView,
    SmartLockViewSet,
    AccessPermissionViewSet,
    AccessEventLogViewSet,
)

router = DefaultRouter()
router.register(r'locks', SmartLockViewSet, basename="locks")
router.register(r'permissions', AccessPermissionViewSet, basename="permissions")
router.register(r'logs', AccessEventLogViewSet, basename="logs")

urlpatterns = [
    path('health/', health, name='Health'),
    path('register/', UserRegisterView.as_view(), name='register'),
    path('login/', UserLoginView.as_view(), name='login'),
    path('me/', UserInfoView.as_view(), name='me'),
    path('', include(router.urls)),
]

from django.urls import path
from .views import UserNotificationsAPIView

urlpatterns = [
    path('notifications/', UserNotificationsAPIView.as_view(), name='user-notifications-list'),
]
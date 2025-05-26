from django.db import models
from approval_system.utils import PhoneNumberField
from approval_system.mixins import TimestampMixin

# Create your models here.
from django.contrib.auth.models import AbstractUser

class AdminUser(AbstractUser, TimestampMixin):
    """
    Custom user model for admin users only
    """
    first_name = models.CharField(max_length=150)
    last_name = models.CharField(max_length=150)
    email = models.EmailField(unique=True)
    username = models.CharField(max_length=255, unique=True, blank=True, null=True)
    email_notification = models.BooleanField(default=False)
    phone_number = models.CharField(max_length=15, null=True, blank=True)
    is_approver = models.BooleanField(default=False)
    is_super_user = models.BooleanField(default=False)
    
    # Override the default required fields
    REQUIRED_FIELDS = ['email', 'first_name', 'last_name']
    
    def __str__(self):
        if self.username:
            return self.username
        return self.email

class Client(TimestampMixin):
    """
    Client model for managing client information
    """
    first_name = models.CharField(max_length=255)
    middle_name = models.CharField(max_length=255, blank=True, null=True)
    last_name = models.CharField(max_length=255)
    mobile_number = PhoneNumberField(blank=True, null=True,verbose_name='mobile_number')
    program = models.CharField(max_length=100)
    date_of_birth = models.DateField(blank=True, null=True)
    
    def __str__(self):
        return f"{self.first_name} ({self.last_name})"
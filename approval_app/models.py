from django.db import models
from approval_system.utils import PhoneNumberField
from approval_system.mixins import TimestampMixin
from approval_system import settings

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
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']
    
    # Override the default required fields
    #REQUIRED_FIELDS = ['email', 'first_name', 'last_name']
    
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
    

class Task(TimestampMixin):
    """
    Task model for managing tasks related to clients
    """
    client_id = models.ForeignKey(Client, on_delete=models.CASCADE, related_name='tasks')
    task = models.CharField(max_length=255)
    task_status = models.CharField(max_length=50, choices=[
        ('pending', 'Pending'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
        ('cancelled', 'Cancelled'),
        ('incomplete', 'Incomplete'),
    ], default='pending')
    task_description = models.TextField(blank=True, null=True)
    task_due_date = models.DateField(blank=True, null=True)
    task_completed_date = models.DateField(blank=True, null=True)
    approver = models.ForeignKey(AdminUser, on_delete=models.CASCADE, related_name='tasks_approver', blank=True, null=True)
    approval_status = models.CharField(max_length=255, null=True, blank=True)
    category = models.OneToOneField(
        'ApproversCategory',
        on_delete=models.CASCADE,
        related_name='approvers_category',
        blank=True,
        null=True
    )
    is_approval_needed = models.BooleanField(default=False)
    approver = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
        related_name='client_task_approvers',
        through='TaskApprover',
        through_fields=('Task', 'approver'),
        blank=True
    )
    class Meta:
        db_table = 'approval_app_task'

    def __str__(self):
        return f"Task for {self.client_id.first_name} {self.client_id.last_name}: {self.task} ({self.task_status})"
    
class TaskApprover(TimestampMixin):
    Task = models.ForeignKey('Task', on_delete=models.CASCADE)
    approver = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name='task_approver_set')
    is_approved_status = models.CharField(max_length=255,null=True,blank=True)

    def __str__(self):
        return f"Approver {self.approver} for Task {self.Task}"

    class Meta:
        db_table = 'task_approvers'
    

class ApproversCategory(TimestampMixin):
    """
    Model to categorize approvers
    """
    category_name = models.CharField(max_length=255, unique=True)
    description = models.TextField(blank=True, null=True)
    approvers = models.ManyToManyField(AdminUser, related_name='approvers_categories', blank=False, null=False)
    class Meta:
        db_table = 'approval_app_approvers_category'

    def __str__(self):
        return self.category_name


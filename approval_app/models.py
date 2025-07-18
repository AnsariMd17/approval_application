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
    approval_status = models.CharField(max_length=255, null=True, blank=True)
    category = models.ForeignKey(
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

class TaskHistory(TimestampMixin):
    """
    Model to track task history and changes
    """
    task = models.ForeignKey('Task', on_delete=models.CASCADE, related_name='task_histories')
    approval_status = models.CharField(max_length=255, choices=[
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
        ('resubmitted', 'Resubmitted'),
        ('self-approved', 'Self-Approved'),
    ])
    task_status = models.CharField(max_length=50, choices=[
        ('pending', 'Pending'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
        ('cancelled', 'Cancelled'),
        ('incomplete', 'Incomplete'),
    ])
    
    class Meta:
        db_table = 'task_history'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"Task {self.task.id} - {self.approval_status} (Status: {self.task_status})"
    

class Stage(TimestampMixin):
    """
    Stage model representing a stage in a category.
    """
    stage_name = models.CharField(max_length=255, null=False, blank=False)
    category = models.ForeignKey('approval_app.ApproversCategory',null=True, blank=True,on_delete=models.CASCADE)
    stage_status = models.CharField(
        max_length=50,
        choices=[
            ('pending', 'Pending'),
            ('in_progress', 'In Progress'),
            ('completed', 'Completed'),
            ('incomplete', 'Incomplete'),
        ],
        default='pending'
    )
    stage_approval_status = models.CharField(
        max_length=50,
        choices=[
            ('pending', 'Pending'),
            ('approved', 'Approved'),
            ('rejected', 'Rejected'),
            ('self-approved', 'Self-Approved'),
        ],
        default='pending'
    )
    stage_approval_needed = models.BooleanField(default=False)
    stage_approvers = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
        through='StageApprover',
        through_fields=('stage', 'approver'),
        related_name='stage_approvers',
        blank=True
    )
    stage_approved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name='stage_approved_by',
        null=True, blank=True,
        on_delete=models.SET_NULL
    )
    stage_rejected_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name='stage_rejected_by',
        null=True, blank=True,
        on_delete=models.SET_NULL
    )
    stage_approved_at = models.DateTimeField(null=True, blank=True)
    stage_rejected_at = models.DateTimeField(null=True, blank=True)
    stage_rejected_reason = models.TextField(null=True, blank=True)

    class Meta:
        db_table = 'approval_app_stage'

    def __str__(self):
        return self.stage_name
    

class StageApprover(TimestampMixin):
    """
    Through model for Stage and Approver (AdminUser) relationship.
    Allows to store approval/rejection status for each stage-approver combo.
    """
    stage = models.ForeignKey(Stage, on_delete=models.CASCADE, related_name='stage_approver_links')
    approver = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='approver_stage_links')
    approval_status = models.CharField(
        max_length=20,
        choices=[
            ('pending', 'Pending'),
            ('approved', 'Approved'),
            ('rejected', 'Rejected'),
        ],
        default='pending'
    )

    class Meta:
        db_table = 'approval_app_stage_approver'
        unique_together = ('stage', 'approver')

    def __str__(self):
        return f"Stage: {self.stage.stage_name} - Approver: {self.approver} ({self.approval_status})"
    

class ApproversCategory(TimestampMixin):
    """
    Model to categorize approvers
    """
    category_name = models.CharField(max_length=255, null=False, blank=False)
    description = models.TextField(blank=True, null=True)
    approvers = models.ManyToManyField(AdminUser, related_name='approvers_categories', blank=True)
    stages = models.ManyToManyField(Stage, related_name='categories_stages', blank=False, null=False)
    class Meta:
        db_table = 'approval_app_approvers_category'

    def __str__(self):
        return self.category_name
from rest_framework import serializers

from .models import Client, AdminUser,ApproversCategory, Task, TaskHistory, Stage
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.contrib.auth import authenticate
from rest_framework.exceptions import AuthenticationFailed
class ClientSerializer(serializers.ModelSerializer):
    tasks = serializers.SerializerMethodField()
    class Meta:
        model = Client
        fields = "__all__"
        extra_fields = ['tasks']

    def get_tasks(self, obj):
        # Get all tasks for this client, prefetch the category for efficiency
        tasks = obj.tasks.select_related('category').all()
        if not tasks:
            return None
        return [
            {
                "task_id": task.id,
                "task": task.task,
                "category_id": task.category.id if task.category else None,
                "category_name": task.category.category_name if task.category else None,
            }
            for task in tasks
        ]


class AdminUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = AdminUser
        exclude = [ 'password', 'last_login', 'is_superuser', 'changed_by', 'created_by', 'created_at', 'changed_at' ]

class CategorySerializer(serializers.ModelSerializer):
    approvers = serializers.PrimaryKeyRelatedField(
        queryset=AdminUser.objects.all(),
        many=True,
        required=False,
        allow_null=True
    )
    class Meta:
        model = ApproversCategory
        fields = "__all__"

    def create(self, validated_data):
        stages_data = validated_data.pop('stages', [])
        category = super().create(validated_data)
        # Create each stage and attach to category
        for stage_data in stages_data:
            stage = Stage.objects.create(**stage_data)
            category.stages.add(stage)
        return category


# class TaskSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = Task
#         fields = "__all__"
#         read_only_fields = ['approver', 'approval_status', 'is_approval_needed', 'approved_by']

class TaskSerializer(serializers.ModelSerializer):
    task_history = serializers.SerializerMethodField()
    class Meta:
        model = Task
        fields = [
            'id', 'client_id', 'task', 'task_status', 'task_description', 
            'task_due_date', 'task_completed_date', 'is_approval_needed', 
            'category', 'approval_status', 'approver', 'created_at', 'task_history'
        ]
        read_only_fields = ['id', 'approver', 'approval_status', 'created_at', 'changed_at']

    def get_task_history(self, obj):
        history_records = TaskHistory.objects.filter(task=obj).order_by('-created_at')
        return TaskHistorySerializer(history_records, many=True).data

class TaskCreateSerializer(serializers.ModelSerializer):
    """
    Serializer specifically for task creation with limited fields
    """
    class Meta:
        model = Task
        fields = [
            'client_id', 'task', 'task_status', 'task_description', 
            'task_due_date', 'task_completed_date', 'is_approval_needed', 'category'
        ]

class SimpleTokenObtainPairSerializer(TokenObtainPairSerializer):
    username_field = 'email'
    
    def validate(self,attrs):
        email = attrs.get('email', '').strip().lower()
        password = attrs.get('password')

        user = authenticate(request=self.context.get('request'),email=email,password=password)

        if not user:
            raise AuthenticationFailed('Invalid email or password. Please try again.')

        if not user.is_active:
            raise AuthenticationFailed('Your account is inactive. Please contact administrator.')
        
        refresh = self.get_token(user)

        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }

class TaskHistorySerializer(serializers.ModelSerializer):
    """
    Serializer for TaskHistory model
    """
    class Meta:
        model = TaskHistory
        fields = [
            'id', 'approval_status', 'task_status', 'created_by', 'created_at'
        ]
        read_only_fields = ['id', 'created_by', 'created_at']


class StageSerializer(serializers.ModelSerializer):
    class Meta:
        model = Stage
        fields = [
            "id",
            "stage_name",
            "stage_status",
            "stage_approval_status",
            "stage_approval_needed",
            "stage_approved_by",
            "stage_rejected_by",
            "stage_approved_at",
            "stage_rejected_at",
            "stage_rejected_reason",
        ]
        read_only_fields = ["id"]
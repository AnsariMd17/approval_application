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

class StageSerializer(serializers.ModelSerializer):
    stage_approvers = serializers.PrimaryKeyRelatedField(
        queryset=AdminUser.objects.all(),
        many=True,
        required=False
    )
    id = serializers.IntegerField(required=False)
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
            "stage_approvers"
        ]
        read_only_fields = ["id"]


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
    stages = StageSerializer(many=True, required=False)
    class Meta:
        model = ApproversCategory
        fields = "__all__"

    def validate(self, attrs):
        approvers = attrs.get('approvers', [])
        stages = self.initial_data.get('stages', [])

        # Convert to set of IDs for easy checking
        category_approver_ids = set([a.id if isinstance(a, AdminUser) else int(a) for a in approvers])

        for idx, stage in enumerate(stages):
            stage_approver_ids = set(stage.get('stage_approvers', []))
            # Validate: stage approvers must be subset of category approvers
            if not stage_approver_ids.issubset(category_approver_ids):
                raise serializers.ValidationError({
                    "stages": [
                        f"stage_approver Ids must be a subset of category approvers IDs."
                    ]
                })
        return attrs


    def create(self, validated_data):
        stages_data = validated_data.pop('stages', [])
        category = super().create(validated_data)
        new_stages = []
        for stage_data in stages_data:
            stage_approvers = stage_data.pop('stage_approvers', [])
            stage_approval_needed = stage_data.get('stage_approval_needed', False)
            if stage_approval_needed:
                stage_data['stage_approval_status'] = 'Pending'
            else:
                stage_data['stage_approval_status'] = 'Self-Approved'
            stage = Stage.objects.create(**stage_data)
            category.stages.add(stage)
            if stage_approvers:
                stage.stage_approvers.set(stage_approvers)
            new_stages.append(stage)
        # Return category and new_stages for use in the view
        self._new_stages = new_stages
        return category
    
    def update(self, instance, validated_data):
        # Update category fields
        instance.category_name = validated_data.get("category_name", instance.category_name)
        instance.description = validated_data.get("description", instance.description)
        instance.save()

        # Update category approvers
        if "approvers" in validated_data:
            instance.approvers.set(validated_data["approvers"])

        stages_data = validated_data.pop('stages', [])
        existing_stages = {s.id: s for s in instance.stages.all()}
        payload_stage_ids = set([s.get('id') for s in stages_data if s.get('id')])

        new_stages = []
        notified_stage_approvers = []  # (stage, [approver_ids])
        for stage_data in stages_data:
            stage_id = stage_data.get('id', None)
            stage_approvers = stage_data.pop('stage_approvers', [])
            # Always convert to IDs for all set logic and .set()
            stage_approver_ids = [a.id if isinstance(a, AdminUser) else int(a) for a in stage_approvers]
            stage_approval_needed = stage_data.get('stage_approval_needed', False)

            if stage_id and stage_id in existing_stages:
                stage = existing_stages[stage_id]
                old_approvers = set(stage.stage_approvers.values_list('id', flat=True))
                new_approvers = set(stage_approver_ids)
                stage.stage_name = stage_data.get("stage_name", stage.stage_name)
                stage.stage_status = stage_data.get("stage_status", stage.stage_status)
                stage.stage_approval_needed = stage_approval_needed

                # Handle approval status & approvers
                if stage_approval_needed:
                    stage.stage_approval_status = "pending"
                    stage.stage_approvers.set(stage_approver_ids)
                    newly_assigned = new_approvers - old_approvers
                    if newly_assigned:
                        notified_stage_approvers.append((stage, newly_assigned))
                else:
                    stage.stage_approvers.clear()
                    stage.stage_approval_status = "self-approved"
                stage.save()
            else:
                # New stage
                if stage_approval_needed:
                    stage_data["stage_approval_status"] = "pending"
                else:
                    stage_data["stage_approval_status"] = "self-approved"
                stage = Stage.objects.create(**stage_data)
                instance.stages.add(stage)
                if stage_approver_ids:
                    stage.stage_approvers.set(stage_approver_ids)
                    if stage_approval_needed:
                        notified_stage_approvers.append((stage, set(stage_approver_ids)))
                new_stages.append(stage)

        self._notified_stage_approvers = notified_stage_approvers
        self._new_stages = new_stages
        return instance


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
